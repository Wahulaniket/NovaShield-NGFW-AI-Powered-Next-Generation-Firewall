# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.87-bookworm AS builder
WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY shared/Cargo.toml shared/Cargo.toml
COPY gateway/Cargo.toml gateway/Cargo.toml
COPY backend/Cargo.toml backend/Cargo.toml

# Create stub source files so cargo can resolve the workspace
RUN mkdir -p shared/src gateway/src backend/src \
    && echo "pub fn stub() {}" > shared/src/lib.rs \
    && echo "fn main() {}" > gateway/src/main.rs \
    && echo "fn main() {}" > backend/src/main.rs

# Build dependencies only (cached layer)
RUN cargo build --release -p gateway 2>/dev/null || true

# Copy real source files
COPY shared/src/ shared/src/
COPY gateway/src/ gateway/src/

# Touch source files to invalidate cache for the real build
RUN touch shared/src/lib.rs gateway/src/main.rs

# Build the gateway binary
RUN cargo build --release -p gateway

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/gateway .
COPY config/gateway.docker.json config/gateway.json

ENV RUST_LOG=gateway=info,tower_http=info
ENV NOVA_CONFIG_PATH=config/gateway.json

EXPOSE 8080 8443

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -sf http://localhost:8080/api/admin/health || exit 1

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["./gateway"]
