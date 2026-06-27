# syntax=docker/dockerfile:1

# cargo-chef splits the build into a cached dependency layer and a thin
# workspace layer: a source-only change no longer rebuilds every crate. The
# Release workflow exports these layers to a registry :buildcache tag
# (cache-to: mode=max), so the cooked dependencies persist across release tags.
FROM rust:1-bookworm AS chef
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl \
    && cargo install cargo-chef --locked
WORKDIR /app

# Distil the dependency graph into recipe.json (changes only when deps change).
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# Cook dependencies from the recipe alone — this layer is reused as long as
# recipe.json is byte-identical, regardless of source edits.
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --locked --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
# Now the real sources; only the workspace crate recompiles past this point.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --target x86_64-unknown-linux-musl --bin porthole

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
