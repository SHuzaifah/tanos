# ── Stage 1: Build ────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace manifests first for Docker layer caching
COPY Cargo.toml ./
COPY tanos-core/Cargo.toml tanos-core/Cargo.toml
COPY tanos-net/Cargo.toml tanos-net/Cargo.toml
COPY tanos-node/Cargo.toml tanos-node/Cargo.toml

# Create dummy source files so `cargo build` can cache dependencies
RUN mkdir -p tanos-core/src tanos-net/src tanos-node/src \
    && echo "pub mod crypto; pub mod identity;" > tanos-core/src/lib.rs \
    && touch tanos-core/src/crypto.rs tanos-core/src/identity.rs \
    && echo "pub mod discovery; pub mod transport; pub mod peers;" > tanos-net/src/lib.rs \
    && touch tanos-net/src/discovery.rs tanos-net/src/transport.rs tanos-net/src/peers.rs \
    && echo "fn main() {}" > tanos-node/src/main.rs \
    && touch tanos-node/src/cli.rs

# Pre-build dependencies (cached layer)
RUN cargo build --release --package tanos-node 2>/dev/null || true

# Now copy the real source code
COPY tanos-core/src tanos-core/src
COPY tanos-net/src tanos-net/src
COPY tanos-node/src tanos-node/src

# Build for real
RUN cargo build --release --package tanos-node

# ── Stage 2: Runtime ──────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/tanos-node /usr/local/bin/tanos-node

# TanOS stores identity in ~/.tanos — Docker uses /root
ENV HOME=/root
ENV RUST_LOG=info

EXPOSE 7700/udp
EXPOSE 7701/tcp

ENTRYPOINT ["tanos-node"]
CMD ["start"]
