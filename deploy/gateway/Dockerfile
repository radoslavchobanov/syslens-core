# Build natively on arm64 or amd64, or select either with Docker Buildx.
FROM rust:1.95.0-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
RUN cargo build --locked --release --package syslens-gateway

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/syslens-gateway /usr/local/bin/syslens-gateway
USER 1000:1000
ENTRYPOINT ["syslens-gateway", "--config", "/etc/syslens-gateway/config.toml"]
CMD ["daemon"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["syslens-gateway", "--config", "/etc/syslens-gateway/config.toml", "health"]
