use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use url::Url;

use crate::error::{AegisError, Result};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "aegis-llm-gateway",
    version,
    about = "AI Cost & Security Gateway: L1/L2 semantic cache, secret redaction, prompt-injection WAF & USD budgets"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Start the AI Cost & Security Gateway HTTP proxy
    Serve(ServeArgs),
    /// Generate a signed offline Pro/Enterprise license key
    Keygen {
        #[arg(long, default_value = "pro")]
        tier: String,
        #[arg(long, default_value_t = 365)]
        days: u64,
        #[arg(
            long,
            env = "AEGIS_LICENSE_SECRET",
            default_value = "aegis-dev-signing-secret"
        )]
        secret: String,
    },
}

#[derive(Debug, Clone, Parser)]
pub struct ServeArgs {
    /// Local address to bind
    #[arg(long, env = "AEGIS_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,

    /// Upstream LLM API base URL
    #[arg(long, env = "AEGIS_UPSTREAM", default_value = "https://api.openai.com")]
    pub upstream: String,

    /// Maximum cache memory budget in MiB
    #[arg(long, env = "AEGIS_MAX_MEMORY_MB", default_value_t = 256)]
    pub max_memory_mb: usize,

    /// Cache entry TTL in seconds
    #[arg(long, env = "AEGIS_TTL_SECS", default_value_t = 86_400)]
    pub ttl_secs: u64,

    /// L2 semantic similarity threshold [0.5..=1.0]
    #[arg(long, env = "AEGIS_SIMILARITY_THRESHOLD", default_value_t = 0.95)]
    pub similarity_threshold: f64,

    /// Daily USD budget per virtual API key (0 = unlimited)
    #[arg(long, env = "AEGIS_MAX_DAILY_USD", default_value_t = 25.0)]
    pub max_daily_usd: f64,

    /// Redact API keys / secrets / PII in outbound prompts before forwarding upstream
    #[arg(long, env = "AEGIS_REDACT_SECRETS", default_value_t = true)]
    pub redact_secrets: bool,

    /// Block prompt-injection & jailbreak attempts with HTTP 403
    #[arg(long, env = "AEGIS_BLOCK_INJECTION", default_value_t = true)]
    pub block_injection: bool,

    /// Optional offline Pro/Enterprise license key
    #[arg(long, env = "AEGIS_LICENSE_KEY")]
    pub license_key: Option<String>,

    /// Signing secret used to verify offline license keys
    #[arg(
        long,
        env = "AEGIS_LICENSE_SECRET",
        default_value = "aegis-dev-signing-secret"
    )]
    pub license_secret: String,
}

impl Default for ServeArgs {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".parse().expect("valid default bind"),
            upstream: "https://api.openai.com".to_string(),
            max_memory_mb: 256,
            ttl_secs: 86_400,
            similarity_threshold: 0.95,
            max_daily_usd: 25.0,
            redact_secrets: true,
            block_injection: true,
            license_key: None,
            license_secret: "aegis-dev-signing-secret".to_string(),
        }
    }
}

impl ServeArgs {
    pub fn validated_upstream(&self) -> Result<String> {
        let parsed = Url::parse(&self.upstream)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(AegisError::Config(format!(
                "unsupported upstream scheme '{}'",
                parsed.scheme()
            )));
        }
        if !(0.5..=1.0).contains(&self.similarity_threshold) {
            return Err(AegisError::Config(
                "similarity_threshold must be between 0.5 and 1.0".into(),
            ));
        }
        Ok(self.upstream.trim_end_matches('/').to_string())
    }
}
