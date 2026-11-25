use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseTier {
    Community,
    Pro,
    Enterprise,
}

impl LicenseTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Community => "community",
            Self::Pro => "pro",
            Self::Enterprise => "enterprise",
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn sign_payload(payload: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(b":");
    hasher.update(payload.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for b in &digest[..16] {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// Generate an offline signed license key: `AEGIS-<TIER>-<EXP_UNIX>-<SIG16>`.
pub fn issue_license(tier: &str, valid_days: u64, secret: &str) -> String {
    let normalized = match tier.to_ascii_lowercase().as_str() {
        "enterprise" => "ENTERPRISE",
        "pro" => "PRO",
        _ => "COMMUNITY",
    };
    let exp = now_secs().saturating_add(valid_days.saturating_mul(86_400));
    let payload = format!("{normalized}-{exp}");
    let sig = sign_payload(&payload, secret);
    format!("AEGIS-{payload}-{sig}")
}

/// Verify an offline license key without any external network call.
pub fn verify_license(key: Option<&str>, secret: &str) -> LicenseTier {
    let Some(raw) = key else {
        return LicenseTier::Community;
    };
    let parts: Vec<&str> = raw.trim().split('-').collect();
    if parts.len() != 4 || parts[0] != "AEGIS" {
        return LicenseTier::Community;
    }
    let tier_str = parts[1];
    let Ok(exp) = parts[2].parse::<u64>() else {
        return LicenseTier::Community;
    };
    if exp <= now_secs() {
        return LicenseTier::Community;
    }
    let payload = format!("{tier_str}-{exp}");
    let expected_sig = sign_payload(&payload, secret);
    if parts[3] != expected_sig {
        return LicenseTier::Community;
    }
    match tier_str {
        "ENTERPRISE" => LicenseTier::Enterprise,
        "PRO" => LicenseTier::Pro,
        _ => LicenseTier::Community,
    }
}
