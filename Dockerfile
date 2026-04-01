# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-or-later

# -- Builder stage ---------------------------------------------------------
# Pin to nightly-slim because rust-toolchain.toml forces nightly and we don't
# want to re-install the toolchain on every build.
FROM rustlang/rust:nightly-slim AS builder

WORKDIR /src

# Install build deps: pkg-config + libclang for any sys-crate bindgen + git
# for build.rs scripts that shell out to git describe. Keep this minimal.
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libclang-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# Copy just the manifests first to maximise layer cache reuse. If only
# source changes, dependency compilation is cached.
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml clippy.toml ./
COPY crates/ ./crates/
COPY tests/ ./tests/

RUN cargo build --release --workspace --bins

# -- Runtime stage ---------------------------------------------------------
# Use debian:trixie-slim (Debian 13) to match the glibc line of
# rustlang/rust:nightly-slim (also trixie-based). A bookworm runtime
# cannot execute the binaries because they link against GLIBC_2.39.
FROM debian:trixie-slim AS runtime

# nftables is the firewall backend fwknoxd drives. ca-certificates is
# needed if the operator ever points cargo-audit/etc. at the image later.
# Everything else the daemon needs (libc, glibc dynamic linker) is already
# in the base image.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system fwknox \
    && useradd --system --gid fwknox --home-dir /var/lib/fwknox \
        --shell /usr/sbin/nologin fwknox \
    && mkdir -p /var/lib/fwknox /run/fwknox /etc/fwknox \
    && chown fwknox:fwknox /var/lib/fwknox /run/fwknox

COPY --from=builder /src/target/release/fwknox  /usr/bin/fwknox
COPY --from=builder /src/target/release/fwknoxd /usr/bin/fwknoxd
COPY config/fwknoxd.toml.example /etc/fwknox/fwknoxd.toml.example

# The operator mounts a real /etc/fwknox/fwknoxd.toml over the example at
# runtime; the example is only here for reference.

EXPOSE 62201/udp
VOLUME ["/var/lib/fwknox"]

# The daemon must start as root to bind the privileged port / init
# nftables / drop privileges itself. The systemd unit and compose file
# provide the capabilities; the image itself stays root-capable.
USER root

ENTRYPOINT ["/usr/bin/fwknoxd"]
CMD ["-c", "/etc/fwknox/fwknoxd.toml"]
