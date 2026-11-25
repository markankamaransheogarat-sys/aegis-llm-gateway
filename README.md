# Aegis AI Gateway (`aegis-llm-gateway`)

**Commercial-grade AI Cost & Security Gateway in `#![forbid(unsafe_code)]` Rust.**

Drop-in reverse proxy in front of OpenAI, Anthropic, or Ollama that simultaneously **cuts API spend by 40–70%** and **prevents data leaks / prompt-injection attacks**.

## Core Capabilities
1. **L1/L2 Sub-Millisecond Semantic Cache**:
   - **L1 Exact Match**: 64-shard `DashMap` with SHA-256 canonicalized JSON/NFKC lookup (`< 10 µs`).
   - **L2 Semantic Similarity**: Zero-dependency 64-bit SimHash + `4×16-bit` inverted index + Top-32 Sparse Cosine (`>= 0.95` default), bounded memory LRU & TTL eviction.
2. **Outbound Secret & PII Redaction**:
   - Automatically scrubs OpenAI (`sk-...`), AWS (`AKIA...`), GitHub (`ghp_...`), JWTs, and PEM private keys before prompts leave your VPC.
3. **Prompt-Injection WAF (`403 Forbidden`)**:
   - Blocks instruction-override attempts, system-prompt exfiltration, and hidden Unicode tag steganography (`U+E0000..U+E007F`).
4. **Per-Key Daily USD Budget Enforcement (`429 Too Many Requests`)**:
   - Estimates token & USD spend per `Authorization: Bearer <key>` across `gpt-4o`, `gpt-4o-mini`, `claude-3.7-sonnet`, `o1`/`o3`, and rejects runaway agents cleanly.
5. **Observability & Licensing**:
   - `GET /healthz`, `GET /metrics` (Prometheus), `GET /admin/stats` (ROI JSON), and offline signed Pro/Enterprise license keys (`aegis-llm-gateway keygen --tier pro --days 365`).

## Quickstart
```bash
docker compose up -d
# or via cargo:
cargo run --release -- serve --bind 0.0.0.0:8080 --upstream https://api.openai.com
```

## Licensing
Community Edition is dual-licensed under MIT OR Apache-2.0. Offline Pro/Enterprise license keys can be generated via `aegis-llm-gateway keygen` and activated with `--license-key AEGIS-PRO-...`.
