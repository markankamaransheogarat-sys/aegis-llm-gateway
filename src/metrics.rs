use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Lock-free atomic telemetry counters for `/metrics`, `/healthz`, and `/admin/stats`.
#[derive(Debug)]
pub struct AegisMetrics {
    pub requests_total: AtomicU64,
    pub l1_hits_total: AtomicU64,
    pub l2_hits_total: AtomicU64,
    pub misses_total: AtomicU64,
    pub tokens_saved_total: AtomicU64,
    pub usd_saved_micros: AtomicU64,
    pub usd_spent_micros: AtomicU64,
    pub secrets_redacted_total: AtomicU64,
    pub injections_blocked_total: AtomicU64,
    pub budget_rejected_total: AtomicU64,
    pub bytes_used: AtomicU64,
    pub entries_count: AtomicU64,
    pub started_at: Instant,
}

impl Default for AegisMetrics {
    fn default() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            l1_hits_total: AtomicU64::new(0),
            l2_hits_total: AtomicU64::new(0),
            misses_total: AtomicU64::new(0),
            tokens_saved_total: AtomicU64::new(0),
            usd_saved_micros: AtomicU64::new(0),
            usd_spent_micros: AtomicU64::new(0),
            secrets_redacted_total: AtomicU64::new(0),
            injections_blocked_total: AtomicU64::new(0),
            budget_rejected_total: AtomicU64::new(0),
            bytes_used: AtomicU64::new(0),
            entries_count: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }
}

impl AegisMetrics {
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn usd_saved(&self) -> f64 {
        self.usd_saved_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    pub fn usd_spent(&self) -> f64 {
        self.usd_spent_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0
    }

    pub fn hit_rate(&self) -> f64 {
        let reqs = self.requests_total.load(Ordering::Relaxed);
        if reqs == 0 {
            return 0.0;
        }
        let hits =
            self.l1_hits_total.load(Ordering::Relaxed) + self.l2_hits_total.load(Ordering::Relaxed);
        hits as f64 / reqs as f64
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP aegis_requests_total Total LLM gateway requests.\n\
             # TYPE aegis_requests_total counter\n\
             aegis_requests_total {}\n\
             # HELP aegis_l1_hits_total L1 exact SHA-256 cache hits.\n\
             # TYPE aegis_l1_hits_total counter\n\
             aegis_l1_hits_total {}\n\
             # HELP aegis_l2_hits_total L2 SimHash semantic cache hits.\n\
             # TYPE aegis_l2_hits_total counter\n\
             aegis_l2_hits_total {}\n\
             # HELP aegis_misses_total Upstream cache misses.\n\
             # TYPE aegis_misses_total counter\n\
             aegis_misses_total {}\n\
             # HELP aegis_tokens_saved_total Tokens served from cache.\n\
             # TYPE aegis_tokens_saved_total counter\n\
             aegis_tokens_saved_total {}\n\
             # HELP aegis_usd_saved_total Estimated USD saved by cache hits.\n\
             # TYPE aegis_usd_saved_total counter\n\
             aegis_usd_saved_total {:.6}\n\
             # HELP aegis_usd_spent_total Estimated USD spent upstream.\n\
             # TYPE aegis_usd_spent_total counter\n\
             aegis_usd_spent_total {:.6}\n\
             # HELP aegis_secrets_redacted_total Outbound prompts scrubbed for secrets/PII.\n\
             # TYPE aegis_secrets_redacted_total counter\n\
             aegis_secrets_redacted_total {}\n\
             # HELP aegis_injections_blocked_total Requests blocked by prompt-injection WAF.\n\
             # TYPE aegis_injections_blocked_total counter\n\
             aegis_injections_blocked_total {}\n\
             # HELP aegis_budget_rejected_total Requests rejected due to daily USD budget cap.\n\
             # TYPE aegis_budget_rejected_total counter\n\
             aegis_budget_rejected_total {}\n",
            self.requests_total.load(Ordering::Relaxed),
            self.l1_hits_total.load(Ordering::Relaxed),
            self.l2_hits_total.load(Ordering::Relaxed),
            self.misses_total.load(Ordering::Relaxed),
            self.tokens_saved_total.load(Ordering::Relaxed),
            self.usd_saved(),
            self.usd_spent(),
            self.secrets_redacted_total.load(Ordering::Relaxed),
            self.injections_blocked_total.load(Ordering::Relaxed),
            self.budget_rejected_total.load(Ordering::Relaxed),
        )
    }
}
