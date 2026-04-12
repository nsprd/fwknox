# syntax=docker/dockerfile:1.7
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Runtime-only image. CI builds the binaries on the runner (fast native
# cargo + Swatinem cache) and copies them in via the build context.
# Expected layout in the context root:
#   dist/fwknox
#   dist/fwknoxd
#   config/fwknoxd.toml.example

FROM debian:trixie-slim

# nftables = firewall backend. fwknoxd makes no outbound TLS calls today
# (no reqwest/rustls/native-tls/openssl in the workspace), so we do not
# ship ca-certificates. Add it back if a future HTTPS config-fetch or
# notification sink lands.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nftables \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system fwknox \
    && useradd --system --gid fwknox --home-dir /var/lib/fwknox \
        --shell /usr/sbin/nologin fwknox \
    && mkdir -p /var/lib/fwknox /run/fwknox /etc/fwknox \
    && chown fwknox:fwknox /var/lib/fwknox /run/fwknox

COPY dist/fwknox  /usr/bin/fwknox
COPY dist/fwknoxd /usr/bin/fwknoxd
COPY config/fwknoxd.toml.example /etc/fwknox/fwknoxd.toml.example

RUN chmod 0755 /usr/bin/fwknox /usr/bin/fwknoxd

EXPOSE 62201/udp
VOLUME ["/var/lib/fwknox"]

# Daemon starts as root to bind the privileged port and init nftables;
# drops privileges itself via fwknox-sandbox.
USER root

ENTRYPOINT ["/usr/bin/fwknoxd"]
CMD ["-c", "/etc/fwknox/fwknoxd.toml"]
