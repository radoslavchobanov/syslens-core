# Build natively on arm64 or amd64, or select either with Docker Buildx.
# rust:1.95.0-bookworm OCI index digest, verified 2026-09-15.
FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
RUN cargo build --locked --release --package syslens-gateway

# debian:bookworm-slim OCI index digest, verified 2026-09-15.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime
COPY --from=builder /build/target/release/syslens-gateway /usr/local/bin/syslens-gateway
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 1000:1000
ENTRYPOINT ["syslens-gateway", "--config", "/etc/syslens-gateway/config.toml"]
CMD ["daemon"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["syslens-gateway", "--config", "/etc/syslens-gateway/config.toml", "health"]
