# syntax=docker/dockerfile:1.7

# --- Builder stage -----------------------------------------------------------
# Uses the slim Debian bookworm Rust image. The slim variant keeps the layer
# small while still providing the C toolchain that some build scripts need
# (ring, blake3).
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

# Copy the manifest and lockfile first so that dependency downloads are cached
# in a separate layer from the application source.
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

# Build the release binary. Cache mounts keep the cargo registry and build
# artifacts across rebuilds, dramatically speeding up iterative builds.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin server && \
    cp target/release/server /server

# --- Runtime stage -----------------------------------------------------------
# Distroless cc-debian12 provides glibc and CA certificates with no shell,
# no package manager, and a tiny attack surface. The nonroot variant runs
# as UID 65534.
FROM gcr.io/distroless/cc-debian12:nonroot

WORKDIR /app

# Copy the statically-linked-enough binary into the image.
COPY --from=builder /server /usr/local/bin/server

# The config and signing key are provided at runtime via volume mounts
# (Kubernetes ConfigMap / Secret). The default config path is /app/config.toml.
EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["server"]
CMD ["/app/config.toml"]
