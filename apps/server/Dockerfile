FROM rust:1.97-bookworm AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock* rustfmt.toml ./
COPY apps/server apps/server
COPY packages packages
RUN cargo build --locked --release -p heartlink-server --no-default-features --features self-hosted

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 heartlink
COPY --from=builder /source/target/release/heartlink-server /usr/local/bin/heartlink-server
USER heartlink
ENV HEARTLINK_DATABASE_HOST=127.0.0.1
ENV HEARTLINK_DATABASE_PORT=3306
ENV HEARTLINK_DATABASE_NAME=heartlink
ENV HEARTLINK_DATABASE_USER=heartlink
ENV HEARTLINK_BIND=0.0.0.0:8787
ENV HEARTLINK_REGISTRATION_ENABLED=true
EXPOSE 8787 8789
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["curl", "--fail", "http://127.0.0.1:8787/health"]
ENTRYPOINT ["heartlink-server"]
