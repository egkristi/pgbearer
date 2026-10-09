# syntax=docker/dockerfile:1.7
#
# Multi-stage build: compile with the Rust toolchain, ship a distroless,
# non-root runtime image containing only the two binaries.

ARG RUST_VERSION=1.97

FROM rust:${RUST_VERSION}-bookworm AS build
# aws-lc-rs (rustls crypto provider) needs cmake and clang.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p pgbearer -p pgbearerctl \
 && install -D -m 0755 target/release/pgbearer /out/pgbearer \
 && install -D -m 0755 target/release/pgbearerctl /out/pgbearerctl

FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="pgbearer" \
      org.opencontainers.image.description="Identity-aware PostgreSQL gateway: OIDC bearer tokens to least-privilege PostgreSQL roles" \
      org.opencontainers.image.source="https://github.com/egkristi/pgbearer" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/pgbearer /out/pgbearerctl /usr/local/bin/
USER nonroot:nonroot
EXPOSE 5432 9090
ENTRYPOINT ["/usr/local/bin/pgbearer"]
CMD ["--config", "/etc/pgbearer/pgbearer.yaml"]
