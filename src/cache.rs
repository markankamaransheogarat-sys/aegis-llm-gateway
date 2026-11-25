use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::metrics::AegisMetrics;

#[derive(Debug, Clone)]
pub struct CanonicalRequest {
    pub model: String,
    pub stream: bool,
    pub l1_key: [u8; 32],
    pub partition_hash: u64,
    pub semantic_text: String,
    pub prompt_tokens_est: u64,
}

#[derive(Debug)]
pub struct CacheEntry {
    pub l1_key: [u8; 32],
    pub partition_hash: u64,
    pub model: String,
    pub simhash: u64,
    pub sparse_vec: Vec<(u64, f32)>,
    pub completion_text: String,
    pub raw_json_body: Option<Vec<u8>>,
    pub tokens_estimate: u64,
    pub usd_cost_micros: u64,
    pub expires_at_secs: u64,
    pub last_accessed_ns: AtomicU64,
    pub approx_bytes: usize,
}

#[derive(Debug, Clone)]
pub enum CacheHit {
    L1Exact(Arc<CacheEntry>),
    L2Semantic {
        entry: Arc<CacheEntry>,
        similarity: f64,
    },
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn hash_feature_64(bytes: &[u8]) -> u64 {
    let mut h = fnv1a_64(bytes);
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

pub fn normalize_text(input: &str) -> String {
    let nfkc: String = input.nfkc().collect();
    let mut out = String::with_capacity(nfkc.len());
    let mut prev_space = false;
    for ch in nfkc.trim().chars() {
        if ch == ' ' || ch == '\t' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

fn sort_json(val: &Value) -> Value {
    match val {
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), sort_json(v));
            }
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json).collect()),
        other => other.clone(),
    }
}

pub fn canonicalize_request(body: &[u8]) -> Option<CanonicalRequest> {
    let root: Value = serde_json::from_slice(body).ok()?;
    let obj = root.as_object()?;
    let model = obj
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();
    let stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let mut prompt_parts = Vec::new();
    if let Some(messages) = obj.get("messages").and_then(Value::as_array) {
        for msg in messages {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
            if let Some(content) = msg.get("content") {
                match content {
                    Value::String(s) => {
                        prompt_parts.push(format!("[{role}] {}", normalize_text(s)))
                    }
                    other => {
                        let ser = serde_json::to_string(&sort_json(other)).unwrap_or_default();
                        prompt_parts.push(format!("[{role}] {}", normalize_text(&ser)));
                    }
                }
            }
        }
    } else {
        let prompt = obj.get("prompt").and_then(Value::as_str)?;
        prompt_parts.push(normalize_text(prompt));
    }

    let canonical_prompt = prompt_parts.join("\n");
    let prompt_tokens_est = (canonical_prompt.len() as u64 / 4).max(1);

    let mut params = Map::new();
    for key in ["temperature", "top_p", "max_tokens", "stop"] {
        if let Some(v) = obj.get(key) {
            params.insert(key.to_string(), sort_json(v));
        }
    }
    let params_json = serde_json::to_string(&Value::Object(params)).unwrap_or_default();

    let mut hasher = Sha256::new();
    hasher.update(model.as_bytes());
    hasher.update(b"\x00");
    hasher.update(canonical_prompt.as_bytes());
    hasher.update(b"\x00");
    hasher.update(params_json.as_bytes());
    let l1_key: [u8; 32] = hasher.finalize().into();
    let partition_hash = fnv1a_64(format!("{model}\x00{params_json}").as_bytes());

    Some(CanonicalRequest {
        model,
        stream,
        l1_key,
        partition_hash,
        semantic_text: canonical_prompt,
        prompt_tokens_est,
    })
}

fn compute_signature(text: &str) -> (u64, Vec<(u64, f32)>) {
    let lower = text.to_ascii_lowercase();
    let mut weights: HashMap<u64, f64> = HashMap::new();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();
    for &w in &words {
        *weights
            .entry(hash_feature_64(format!("w:{w}").as_bytes()))
            .or_insert(0.0) += 1.5;
    }
    for pair in words.windows(2) {
        *weights
            .entry(hash_feature_64(
                format!("b:{}_{}", pair[0], pair[1]).as_bytes(),
            ))
            .or_insert(0.0) += 1.25;
    }

    let mut accum = [0.0_f64; 64];
    for (&h, &w) in &weights {
        for (bit, slot) in accum.iter_mut().enumerate() {
            if (h >> bit) & 1 == 1 {
                *slot += w;
            } else {
                *slot -= w;
            }
        }
    }
    let mut simhash = 0_u64;
    for (bit, &v) in accum.iter().enumerate() {
        if v >= 0.0 {
            simhash |= 1_u64 << bit;
        }
    }

    let mut entries: Vec<(u64, f64)> = weights.into_iter().collect();
    entries.sort_by(|a, b| b.1.total_cmp(&a.1));
    entries.truncate(32);
    let norm = entries.iter().map(|(_, w)| w * w).sum::<f64>().sqrt();
    let mut sparse: Vec<(u64, f32)> = if norm > 0.0 {
        entries
            .into_iter()
            .map(|(h, w)| (h, (w / norm) as f32))
            .collect()
    } else {
        Vec::new()
    };
    sparse.sort_unstable_by_key(|(h, _)| *h);
    (simhash, sparse)
}

#[inline]
fn sparse_cosine(a: &[(u64, f32)], b: &[(u64, f32)]) -> f64 {
    let (mut i, mut j, mut dot) = (0, 0, 0.0_f64);
    while i < a.len() && j < b.len() {
        match a[i].0.cmp(&b[j].0) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                dot += f64::from(a[i].1) * f64::from(b[j].1);
                i += 1;
                j += 1;
            }
        }
    }
    dot.clamp(0.0, 1.0)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos() as u64
}

pub struct CacheEngine {
    l1: DashMap<[u8; 32], Arc<CacheEntry>>,
    l2_blocks: [DashMap<u16, Vec<[u8; 32]>>; 4],
    max_memory_bytes: usize,
    ttl_secs: u64,
    similarity_threshold: f64,
    metrics: Arc<AegisMetrics>,
}

impl CacheEngine {
    pub fn new(
        max_memory_mb: usize,
        ttl_secs: u64,
        similarity_threshold: f64,
        metrics: Arc<AegisMetrics>,
    ) -> Self {
        Self {
            l1: DashMap::with_shard_amount(64),
            l2_blocks: [
                DashMap::with_shard_amount(32),
                DashMap::with_shard_amount(32),
                DashMap::with_shard_amount(32),
                DashMap::with_shard_amount(32),
            ],
            max_memory_bytes: max_memory_mb.max(1) * 1024 * 1024,
            ttl_secs,
            similarity_threshold,
            metrics,
        }
    }

    pub fn lookup(&self, req: &CanonicalRequest) -> Option<CacheHit> {
        let now = now_secs();
        if let Some(r) = self.l1.get(&req.l1_key) {
            let entry = Arc::clone(r.value());
            drop(r);
            if entry.expires_at_secs > now {
                entry.last_accessed_ns.store(now_nanos(), Ordering::Relaxed);
                return Some(CacheHit::L1Exact(entry));
            }
            self.remove_entry(&req.l1_key);
        }

        let (simhash, sparse) = compute_signature(&req.semantic_text);
        let mut seen = HashSet::new();
        for (band, table) in self.l2_blocks.iter().enumerate() {
            let chunk = ((simhash >> (band * 16)) & 0xffff) as u16;
            if let Some(keys) = table.get(&chunk) {
                for k in keys.iter() {
                    seen.insert(*k);
                }
            }
        }

        let mut best: Option<(Arc<CacheEntry>, f64)> = None;
        for key in seen {
            let Some(r) = self.l1.get(&key) else {
                continue;
            };
            let entry = Arc::clone(r.value());
            drop(r);
            if entry.expires_at_secs <= now {
                self.remove_entry(&key);
                continue;
            }
            if entry.partition_hash != req.partition_hash {
                continue;
            }
            if (simhash ^ entry.simhash).count_ones() > 10 {
                continue;
            }
            let cos = sparse_cosine(&sparse, &entry.sparse_vec);
            if cos >= self.similarity_threshold && best.as_ref().map_or(true, |(_, b)| cos > *b) {
                best = Some((entry, cos));
            }
        }

        best.map(|(entry, similarity)| {
            entry.last_accessed_ns.store(now_nanos(), Ordering::Relaxed);
            CacheHit::L2Semantic { entry, similarity }
        })
    }

    pub fn insert(
        &self,
        req: &CanonicalRequest,
        completion_text: String,
        raw_json_body: Option<Vec<u8>>,
        tokens_estimate: u64,
        usd_cost_micros: u64,
    ) {
        let (simhash, sparse_vec) = compute_signature(&req.semantic_text);
        let raw_len = raw_json_body.as_ref().map_or(0, Vec::len);
        let approx_bytes =
            256 + req.model.len() + completion_text.len() + raw_len + sparse_vec.len() * 16;
        let now = now_secs();
        let entry = Arc::new(CacheEntry {
            l1_key: req.l1_key,
            partition_hash: req.partition_hash,
            model: req.model.clone(),
            simhash,
            sparse_vec,
            completion_text,
            raw_json_body,
            tokens_estimate: tokens_estimate.max(1),
            usd_cost_micros,
            expires_at_secs: now.saturating_add(self.ttl_secs),
            last_accessed_ns: AtomicU64::new(now_nanos()),
            approx_bytes,
        });

        if let Some(prev) = self.l1.insert(req.l1_key, entry) {
            self.metrics
                .bytes_used
                .fetch_sub(prev.approx_bytes as u64, Ordering::Relaxed);
        } else {
            self.metrics.entries_count.fetch_add(1, Ordering::Relaxed);
        }
        self.metrics
            .bytes_used
            .fetch_add(approx_bytes as u64, Ordering::Relaxed);
        for (band, table) in self.l2_blocks.iter().enumerate() {
            let chunk = ((simhash >> (band * 16)) & 0xffff) as u16;
            table.entry(chunk).or_default().push(req.l1_key);
        }

        let high_wm = (self.max_memory_bytes * 9) / 10;
        let low_wm = (self.max_memory_bytes * 8) / 10;
        if self.metrics.bytes_used.load(Ordering::Relaxed) as usize > high_wm {
            let mut lru: Vec<([u8; 32], u64)> = self
                .l1
                .iter()
                .map(|r| (*r.key(), r.value().last_accessed_ns.load(Ordering::Relaxed)))
                .collect();
            lru.sort_unstable_by_key(|(_, ts)| *ts);
            for (k, _) in lru {
                if self.metrics.bytes_used.load(Ordering::Relaxed) as usize <= low_wm {
                    break;
                }
                self.remove_entry(&k);
            }
        }
    }

    fn remove_entry(&self, key: &[u8; 32]) {
        if let Some((_, removed)) = self.l1.remove(key) {
            self.metrics
                .bytes_used
                .fetch_sub(removed.approx_bytes as u64, Ordering::Relaxed);
            self.metrics.entries_count.fetch_sub(1, Ordering::Relaxed);
            for (band, table) in self.l2_blocks.iter().enumerate() {
                let chunk = ((removed.simhash >> (band * 16)) & 0xffff) as u16;
                if let Some(mut list) = table.get_mut(&chunk) {
                    list.retain(|k| k != key);
                }
            }
        }
    }
}
