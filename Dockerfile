# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --locked --release --target x86_64-unknown-linux-musl

FROM alpine:3.22

RUN addgroup -S porthole \
    && adduser -S -D -H -h /var/lib/porthole -G porthole porthole \
    && mkdir -p /var/lib/porthole \
    && chown -R porthole:porthole /var/lib/porthole

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/porthole /usr/local/bin/porthole
COPY docker/entrypoint.sh /usr/local/bin/porthole-entrypoint

RUN chmod 0755 /usr/local/bin/porthole /usr/local/bin/porthole-entrypoint

USER porthole
WORKDIR /var/lib/porthole
VOLUME ["/var/lib/porthole"]

ENTRYPOINT ["porthole-entrypoint"]
CMD ["server"]
