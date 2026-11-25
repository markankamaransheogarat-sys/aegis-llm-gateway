use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use futures_util::stream::{self, StreamExt};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::cache::{canonicalize_request, CacheEngine, CacheHit};
use crate::config::ServeArgs;
use crate::error::Result;
use crate::license::{verify_license, LicenseTier};
use crate::metrics::AegisMetrics;
use crate::security::{estimate_cost_micros, SecurityFirewall};

#[derive(Clone)]
pub struct AppState {
    pub cache: Arc<CacheEngine>,
    pub firewall: Arc<SecurityFirewall>,
    pub metrics: Arc<AegisMetrics>,
    pub upstream: String,
    pub client: reqwest::Client,
    pub tier: LicenseTier,
}

pub fn build_router(cfg: &ServeArgs) -> Result<Router> {
    let upstream = cfg.validated_upstream()?;
    let tier = verify_license(cfg.license_key.as_deref(), &cfg.license_secret);
    let metrics = Arc::new(AegisMetrics::default());
    let cache = Arc::new(CacheEngine::new(
        cfg.max_memory_mb,
        cfg.ttl_secs,
        cfg.similarity_threshold,
        Arc::clone(&metrics),
    ));
    let firewall = Arc::new(SecurityFirewall::new(
        cfg.redact_secrets,
        cfg.block_injection,
        cfg.max_daily_usd,
    )?);

    let state = AppState {
        cache,
        firewall,
        metrics,
        upstream,
        client: reqwest::Client::new(),
        tier,
    };

    Ok(Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/metrics", get(handle_metrics))
        .route("/admin/stats", get(handle_admin_stats))
        .route("/v1/chat/completions", post(handle_llm_post))
        .route("/v1/completions", post(handle_llm_post))
        .route("/v1/messages", post(handle_llm_post))
        .with_state(state))
}

pub async fn run_server(cfg: ServeArgs) -> Result<()> {
    let router = build_router(&cfg)?;
    let listener = TcpListener::bind(cfg.bind).await?;
    tracing::info!(
        "aegis-llm-gateway listening on http://{} -> {} (tier={})",
        cfg.bind,
        cfg.upstream,
        verify_license(cfg.license_key.as_deref(), &cfg.license_secret).as_str()
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn handle_healthz(State(state): State<AppState>) -> Response {
    let body = json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "tier": state.tier.as_str(),
        "uptime_secs": state.metrics.uptime_secs(),
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

async fn handle_metrics(State(state): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render_prometheus(),
    )
        .into_response()
}

async fn handle_admin_stats(State(state): State<AppState>) -> Response {
    let body = json!({
        "tier": state.tier.as_str(),
        "requests_total": state.metrics.requests_total.load(Ordering::Relaxed),
        "l1_hits": state.metrics.l1_hits_total.load(Ordering::Relaxed),
        "l2_hits": state.metrics.l2_hits_total.load(Ordering::Relaxed),
        "misses": state.metrics.misses_total.load(Ordering::Relaxed),
        "hit_rate": state.metrics.hit_rate(),
        "tokens_saved": state.metrics.tokens_saved_total.load(Ordering::Relaxed),
        "usd_saved": state.metrics.usd_saved(),
        "usd_spent": state.metrics.usd_spent(),
        "secrets_redacted": state.metrics.secrets_redacted_total.load(Ordering::Relaxed),
        "injections_blocked": state.metrics.injections_blocked_total.load(Ordering::Relaxed),
        "budget_rejected": state.metrics.budget_rejected_total.load(Ordering::Relaxed),
        "entries": state.metrics.entries_count.load(Ordering::Relaxed),
        "bytes_used": state.metrics.bytes_used.load(Ordering::Relaxed),
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn extract_api_key(headers: &HeaderMap) -> String {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.strip_prefix("Bearer ").unwrap_or(s).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "anonymous".to_string())
}

async fn handle_llm_post(State(state): State<AppState>, req: Request) -> Response {
    let started = Instant::now();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/v1/chat/completions".to_string());
    let req_headers = req.headers().clone();
    let api_key = extract_api_key(&req_headers);

    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    if !state.firewall.check_budget(&api_key) {
        state
            .metrics
            .budget_rejected_total
            .fetch_add(1, Ordering::Relaxed);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::CONTENT_TYPE, "application/json")],
            json!({"error": {"code": "budget_exceeded", "message": "Daily USD budget exceeded"}})
                .to_string(),
        )
            .into_response();
    }

    let raw_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid body: {e}")).into_response();
        }
    };

    let (scrubbed_bytes, redactions) = match state.firewall.inspect_and_scrub(&raw_bytes) {
        Ok(res) => res,
        Err(reason) => {
            state
                .metrics
                .injections_blocked_total
                .fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::FORBIDDEN,
                [
                    (
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    ),
                    (
                        HeaderName::from_static("x-aegis-blocked"),
                        HeaderValue::from_static("prompt-injection"),
                    ),
                ]
                .into_iter()
                .collect::<HeaderMap>(),
                json!({"error": {"code": "prompt_injection_blocked", "message": reason}})
                    .to_string(),
            )
                .into_response();
        }
    };
    if redactions > 0 {
        state
            .metrics
            .secrets_redacted_total
            .fetch_add(redactions as u64, Ordering::Relaxed);
    }

    let Some(canon) = canonicalize_request(&scrubbed_bytes) else {
        return (StatusCode::BAD_REQUEST, "missing messages or prompt").into_response();
    };

    if let Some(hit) = state.cache.lookup(&canon) {
        let elapsed_us = started.elapsed().as_micros();
        let (status_label, sim_str, entry) = match hit {
            CacheHit::L1Exact(entry) => {
                state.metrics.l1_hits_total.fetch_add(1, Ordering::Relaxed);
                ("HIT-L1", "1.0000".to_string(), entry)
            }
            CacheHit::L2Semantic { entry, similarity } => {
                state.metrics.l2_hits_total.fetch_add(1, Ordering::Relaxed);
                ("HIT-L2", format!("{similarity:.4}"), entry)
            }
        };
        state
            .metrics
            .tokens_saved_total
            .fetch_add(entry.tokens_estimate, Ordering::Relaxed);
        state
            .metrics
            .usd_saved_micros
            .fetch_add(entry.usd_cost_micros, Ordering::Relaxed);

        let mut resp = if canon.stream {
            let sse_stream = synthesize_sse(canon.model, entry.completion_text.clone());
            let mut r = Response::new(Body::from_stream(sse_stream));
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            r
        } else {
            let body = entry
                .raw_json_body
                .clone()
                .unwrap_or_else(|| json!({"choices":[{"message":{"role":"assistant","content":entry.completion_text}}]}).to_string().into_bytes());
            let mut r = Response::new(Body::from(body));
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            r
        };
        attach_headers(
            resp.headers_mut(),
            status_label,
            &sim_str,
            elapsed_us,
            redactions,
        );
        return resp;
    }

    state.metrics.misses_total.fetch_add(1, Ordering::Relaxed);
    let target_url = format!("{}{}", state.upstream, path_and_query);
    let mut builder = state.client.post(&target_url);
    for (name, value) in &req_headers {
        if matches!(
            name.as_str().to_ascii_lowercase().as_str(),
            "host" | "content-length" | "connection" | "transfer-encoding"
        ) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    builder = builder.body(scrubbed_bytes);

    let upstream_resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        if matches!(
            name.as_str().to_ascii_lowercase().as_str(),
            "content-length" | "connection" | "transfer-encoding"
        ) {
            continue;
        }
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            resp_headers.insert(n, v);
        }
    }

    let is_sse = upstream_resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/event-stream"));

    if is_sse && status.is_success() {
        let (tx, rx) = mpsc::channel::<Bytes>(64);
        let cache = Arc::clone(&state.cache);
        let metrics = Arc::clone(&state.metrics);
        let firewall = Arc::clone(&state.firewall);
        let key_clone = api_key.clone();
        let mut upstream_stream = upstream_resp.bytes_stream();

        tokio::spawn(async move {
            let mut acc = String::new();
            while let Some(Ok(chunk)) = upstream_stream.next().await {
                if let Ok(text) = std::str::from_utf8(&chunk) {
                    for line in text.lines() {
                        if let Some(payload) = line.trim().strip_prefix("data:") {
                            let p = payload.trim();
                            if p != "[DONE]" {
                                if let Ok(v) = serde_json::from_str::<Value>(p) {
                                    if let Some(d) = v
                                        .pointer("/choices/0/delta/content")
                                        .and_then(Value::as_str)
                                    {
                                        acc.push_str(d);
                                    }
                                }
                            }
                        }
                    }
                }
                if tx.send(chunk).await.is_err() {
                    break;
                }
            }
            if !acc.is_empty() {
                let comp_tokens = (acc.len() as u64 / 4).max(1);
                let cost = estimate_cost_micros(&canon.model, canon.prompt_tokens_est, comp_tokens);
                metrics.usd_spent_micros.fetch_add(cost, Ordering::Relaxed);
                firewall.record_spend(&key_clone, cost);
                cache.insert(
                    &canon,
                    acc,
                    None,
                    canon.prompt_tokens_est + comp_tokens,
                    cost,
                );
            }
        });

        let stream_out = stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|b| (Ok::<Bytes, Infallible>(b), rx))
        });
        let mut resp = Response::new(Body::from_stream(stream_out));
        *resp.status_mut() = status;
        *resp.headers_mut() = resp_headers;
        attach_headers(
            resp.headers_mut(),
            "MISS",
            "0.0000",
            started.elapsed().as_micros(),
            redactions,
        );
        return resp;
    }

    let resp_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("read error: {e}")).into_response(),
    };

    if status.is_success() {
        if let Ok(v) = serde_json::from_slice::<Value>(&resp_bytes) {
            if let Some(content) = v
                .pointer("/choices/0/message/content")
                .and_then(Value::as_str)
                .or_else(|| v.pointer("/content/0/text").and_then(Value::as_str))
            {
                let comp_tokens = v
                    .pointer("/usage/completion_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or_else(|| (content.len() as u64 / 4).max(1));
                let total_tokens = v
                    .pointer("/usage/total_tokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(canon.prompt_tokens_est + comp_tokens);
                let cost = estimate_cost_micros(&canon.model, canon.prompt_tokens_est, comp_tokens);
                state
                    .metrics
                    .usd_spent_micros
                    .fetch_add(cost, Ordering::Relaxed);
                state.firewall.record_spend(&api_key, cost);
                state.cache.insert(
                    &canon,
                    content.to_string(),
                    Some(resp_bytes.to_vec()),
                    total_tokens,
                    cost,
                );
            }
        }
    }

    attach_headers(
        &mut resp_headers,
        "MISS",
        "0.0000",
        started.elapsed().as_micros(),
        redactions,
    );
    let mut resp = Response::new(Body::from(resp_bytes));
    *resp.status_mut() = status;
    *resp.headers_mut() = resp_headers;
    resp
}

fn attach_headers(
    headers: &mut HeaderMap,
    status: &str,
    sim: &str,
    latency_us: u128,
    redactions: usize,
) {
    if let Ok(v) = HeaderValue::from_str(status) {
        headers.insert(HeaderName::from_static("x-cache-status"), v);
    }
    if let Ok(v) = HeaderValue::from_str(sim) {
        headers.insert(HeaderName::from_static("x-cache-similarity"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&latency_us.to_string()) {
        headers.insert(HeaderName::from_static("x-cache-latency-us"), v);
    }
    if redactions > 0 {
        if let Ok(v) = HeaderValue::from_str(&redactions.to_string()) {
            headers.insert(HeaderName::from_static("x-aegis-redactions"), v);
        }
    }
}

fn synthesize_sse(
    model: String,
    text: String,
) -> impl futures_util::stream::Stream<Item = std::result::Result<Bytes, Infallible>> + Send + 'static
{
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let events = vec![
        format!(
            "data: {}\n\n",
            json!({"id": format!("chatcmpl-aegis-{ts}"), "object":"chat.completion.chunk","model":model,"choices":[{"index":0,"delta":{"role":"assistant","content":text},"finish_reason":null}]})
        ),
        format!(
            "data: {}\n\n",
            json!({"id": format!("chatcmpl-aegis-{ts}"), "object":"chat.completion.chunk","model":model,"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]})
        ),
        "data: [DONE]\n\n".to_string(),
    ];
    stream::iter(events.into_iter().map(|s| Ok(Bytes::from(s))))
}
