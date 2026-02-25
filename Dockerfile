# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/ipv6-username-socks5 /usr/local/bin/ipv6-username-socks5

ENV RUST_LOG=info \
    SOCKS5_LISTEN_PORT=1080 \
    SOCKS5_REQUEST_TIMEOUT_SECS=10 \
    SOCKS5_SHUTDOWN_GRACE_SECS=30 \
    SOCKS5_MAX_CONNECTIONS=1024

EXPOSE 1080/tcp

ENTRYPOINT ["/usr/local/bin/ipv6-username-socks5"]
