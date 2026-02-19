# Stage 1: Build compatmalloc from source
FROM rust:1-bookworm AS builder

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends clang lld && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/

RUN RUSTFLAGS="-Clink-arg=-fuse-ld=lld" \
    cargo build --workspace --release && \
    strip target/release/libcompatmalloc.so

# Stage 2: Minimal output — just the .so file
FROM scratch AS artifact
COPY --from=builder /build/target/release/libcompatmalloc.so /libcompatmalloc.so

# Stage 3: Harden any Debian-based application
FROM debian:bookworm-slim AS hardened-base
COPY --from=builder /build/target/release/libcompatmalloc.so /usr/lib/libcompatmalloc.so
ENV LD_PRELOAD=/usr/lib/libcompatmalloc.so
