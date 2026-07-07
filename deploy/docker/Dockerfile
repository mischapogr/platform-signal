# syntax=docker/dockerfile:1
# Native target builds keep AMD64 and ARM64 on the same toolchain.
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY apps ./apps
COPY tests ./tests
COPY benchmarks ./benchmarks
RUN cargo build --locked --release -p signal-server -p signal-agent
COPY deploy/docker/healthcheck.rs /tmp/signal-healthcheck.rs
RUN rustc --edition=2024 -D warnings -C opt-level=s -C strip=symbols \
    /tmp/signal-healthcheck.rs -o /usr/local/bin/signal-healthcheck \
    && mkdir -p /runtime/var/lib/signal /runtime/etc/signal/rules

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2 AS runtime
LABEL org.opencontainers.image.title="PLATFORM::SIGNAL" \
      org.opencontainers.image.description="Durable event queries and findings" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /build/target/release/signal-server /usr/local/bin/signal-server
COPY --from=build /build/target/release/signal-agent /usr/local/bin/signal-agent
COPY --from=build /usr/local/bin/signal-healthcheck /usr/local/bin/signal-healthcheck
COPY --from=build --chown=65532:65532 /runtime/ /
COPY LICENSE /usr/share/licenses/platform-signal/LICENSE
USER 65532:65532
WORKDIR /var/lib/signal
EXPOSE 8080 9090
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/signal-healthcheck"]
ENTRYPOINT ["/usr/local/bin/signal-server"]
