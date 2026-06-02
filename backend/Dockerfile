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
RUN cargo build --release -p backend 2>/dev/null || true

# Copy real source files
COPY shared/src/ shared/src/
COPY backend/src/ backend/src/

# Touch source files to invalidate cache for the real build
RUN touch shared/src/lib.rs backend/src/main.rs

# Build the backend binary
RUN cargo build --release -p backend

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/backend .
COPY config/backend.docker.json config/backend.json

ENV RUST_LOG=backend=info,tower_http=info
ENV NOVA_CONFIG_PATH=config/backend.json

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -sf http://localhost:8081/health || exit 1

ENTRYPOINT ["./backend"]
