# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Multistage build: compile inside the builder stage, ship only the
# runtime-needed bits in the final image. `docker build .` produces a
# working image from a clean checkout with no prior cargo invocation.
#
# Builder base is `rustlang/rust:nightly-bookworm-slim` so nightly is
# preloaded (no rustup download on first build). `rust-toolchain.toml`
# pins the channel; if the pinned channel is newer than the image's
# baked-in nightly, rustup refetches, which hits the BuildKit cache
# mount on `/usr/local/rustup` on subsequent builds.
#
# Builder is Debian 12 (bookworm, glibc 2.36), runtime is Debian 13
# (trixie, glibc ≥2.40). Dynamic-linked binaries built against older
# glibc run on newer glibc, not the reverse — order is correct.

FROM rustlang/rust:nightly-bookworm-slim AS builder

WORKDIR /build

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tests ./tests

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/rustup \
    --mount=type=cache,target=/build/target \
    cargo build --release --workspace --bins \
 && mkdir -p /out \
 && cp target/release/fwknox  /out/fwknox \
 && cp target/release/fwknoxd /out/fwknoxd

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system fwknox \
    && useradd --system --gid fwknox --home-dir /var/lib/fwknox \
        --shell /usr/sbin/nologin fwknox \
    && mkdir -p /var/lib/fwknox /run/fwknox /etc/fwknox \
    && chown fwknox:fwknox /var/lib/fwknox /run/fwknox

COPY --from=builder /out/fwknox  /usr/bin/fwknox
COPY --from=builder /out/fwknoxd /usr/bin/fwknoxd
COPY config/fwknoxd.toml.example /etc/fwknox/fwknoxd.toml.example

RUN chmod 0755 /usr/bin/fwknox /usr/bin/fwknoxd

EXPOSE 62201/udp
VOLUME ["/var/lib/fwknox"]

# Daemon starts as root to bind the privileged port and init nftables;
# drops privileges itself via fwknox-sandbox.
USER root

ENTRYPOINT ["/usr/bin/fwknoxd"]
CMD ["-c", "/etc/fwknox/fwknoxd.toml"]
