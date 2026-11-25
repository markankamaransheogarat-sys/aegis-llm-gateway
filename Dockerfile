FROM rust:1.83-slim-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/aegis-llm-gateway /usr/local/bin/aegis-llm-gateway
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aegis-llm-gateway"]
