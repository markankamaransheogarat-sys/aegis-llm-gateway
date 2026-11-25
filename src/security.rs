use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use regex::Regex;
use serde_json::Value;

use crate::error::Result;

/// Estimate USD cost per 1M tokens (`(input_per_1m, output_per_1m)`).
pub fn model_pricing_usd_per_1m(model: &str) -> (f64, f64) {
    let m = model.to_ascii_lowercase();
    if m.contains("gpt-4o-mini") {
        (0.15, 0.60)
    } else if m.contains("gpt-4o") {
        (2.50, 10.00)
    } else if m.contains("claude-3-7") || m.contains("claude-3.7") || m.contains("sonnet") {
        (3.00, 15.00)
    } else if m.contains("haiku") {
        (0.80, 4.00)
    } else if m.contains("o1") || m.contains("o3") {
        (15.00, 60.00)
    } else {
        (1.00, 3.00)
    }
}

pub fn estimate_cost_micros(model: &str, prompt_tokens: u64, completion_tokens: u64) -> u64 {
    let (in_rate, out_rate) = model_pricing_usd_per_1m(model);
    let usd = (prompt_tokens as f64 * in_rate + completion_tokens as f64 * out_rate) / 1_000_000.0;
    (usd * 1_000_000.0).round().max(1.0) as u64
}

#[derive(Debug, Clone)]
struct BudgetBucket {
    day_index: u64,
    spent_micros: u64,
}

/// Outbound security firewall: secret redaction, prompt-injection detection, and per-key USD budgets.
pub struct SecurityFirewall {
    secret_rules: Vec<(&'static str, Regex)>,
    injection_rules: Vec<(&'static str, Regex)>,
    budgets: DashMap<String, BudgetBucket>,
    max_daily_micros: u64,
    pub redact_secrets: bool,
    pub block_injection: bool,
}

impl SecurityFirewall {
    pub fn new(redact_secrets: bool, block_injection: bool, max_daily_usd: f64) -> Result<Self> {
        let secret_rules = vec![
            ("openai_key", Regex::new(r"sk-[A-Za-z0-9_-]{20,}")?),
            ("aws_key", Regex::new(r"AKIA[0-9A-Z]{16}")?),
            (
                "github_pat",
                Regex::new(r"(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}")?,
            ),
            (
                "pem_private_key",
                Regex::new(
                    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
                )?,
            ),
            (
                "jwt_token",
                Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")?,
            ),
        ];

        let injection_rules = vec![
            (
                "instruction_override",
                Regex::new(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions")?,
            ),
            (
                "system_prompt_exfil",
                Regex::new(
                    r"(?i)(?:reveal|print|dump|output)\s+(?:your|the)\s+(?:system\s+prompt|hidden\s+instructions)",
                )?,
            ),
            (
                "jailbreak_dan",
                Regex::new(r"(?i)\b(?:DAN|do\s+anything\s+now)\b.*?(?:bypass|unrestricted)")?,
            ),
        ];

        let max_daily_micros = if max_daily_usd <= 0.0 {
            0
        } else {
            (max_daily_usd * 1_000_000.0).round() as u64
        };

        Ok(Self {
            secret_rules,
            injection_rules,
            budgets: DashMap::new(),
            max_daily_micros,
            redact_secrets,
            block_injection,
        })
    }

    fn current_day_index() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs()
            / 86_400
    }

    /// Check whether `api_key` still has remaining daily USD budget.
    pub fn check_budget(&self, api_key: &str) -> bool {
        if self.max_daily_micros == 0 {
            return true;
        }
        let today = Self::current_day_index();
        match self.budgets.get(api_key) {
            Some(bucket) if bucket.day_index == today => {
                bucket.spent_micros < self.max_daily_micros
            }
            _ => true,
        }
    }

    /// Record USD spend (in micro-dollars) against `api_key`.
    pub fn record_spend(&self, api_key: &str, micros: u64) {
        if self.max_daily_micros == 0 {
            return;
        }
        let today = Self::current_day_index();
        let mut entry = self
            .budgets
            .entry(api_key.to_string())
            .or_insert_with(|| BudgetBucket {
                day_index: today,
                spent_micros: 0,
            });
        if entry.day_index != today {
            entry.day_index = today;
            entry.spent_micros = 0;
        }
        entry.spent_micros = entry.spent_micros.saturating_add(micros);
    }

    /// Inspect and optionally scrub JSON request body; returns `Err(reason)` if blocked.
    pub fn inspect_and_scrub(&self, body: &[u8]) -> std::result::Result<(Vec<u8>, usize), String> {
        let Ok(mut val) = serde_json::from_slice::<Value>(body) else {
            return Ok((body.to_vec(), 0));
        };

        let mut redactions = 0usize;
        self.visit_value(&mut val, &mut redactions)?;

        if redactions == 0 {
            Ok((body.to_vec(), 0))
        } else {
            let scrubbed = serde_json::to_vec(&val).unwrap_or_else(|_| body.to_vec());
            Ok((scrubbed, redactions))
        }
    }

    fn visit_value(
        &self,
        val: &mut Value,
        redactions: &mut usize,
    ) -> std::result::Result<(), String> {
        match val {
            Value::String(s) => {
                if self.block_injection {
                    if s.chars().any(|c| ('\u{E0000}'..='\u{E007F}').contains(&c)) {
                        return Err("hidden Unicode tag characters detected".to_string());
                    }
                    for (name, re) in &self.injection_rules {
                        if re.is_match(s) {
                            return Err(format!("prompt injection pattern '{name}' detected"));
                        }
                    }
                }
                if self.redact_secrets {
                    let mut current = s.clone();
                    for (label, re) in &self.secret_rules {
                        if re.is_match(&current) {
                            *redactions += 1;
                            current = re
                                .replace_all(&current, format!("[REDACTED:{label}]"))
                                .into_owned();
                        }
                    }
                    *s = current;
                }
                Ok(())
            }
            Value::Array(items) => {
                for item in items {
                    self.visit_value(item, redactions)?;
                }
                Ok(())
            }
            Value::Object(map) => {
                for (_, v) in map {
                    self.visit_value(v, redactions)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
