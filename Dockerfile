FROM rustlang/rust:nightly AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY --from=builder /app/target/release/pathbuster /usr/local/bin/pathbuster
COPY --from=builder /app/wordlists /opt/pathbuster/wordlists
COPY --from=builder /app/payloads /opt/pathbuster/payloads
COPY --from=builder /app/config.yml /opt/pathbuster/config.yml

ENTRYPOINT ["pathbuster"]
