# REL-3 cutover marker: touching this file makes the last build-based auto-update
# rebuild locally and tag the image as the new GHCR ref, so every box switches to
# the prebuilt-image (pull) model cleanly even without reaching ghcr.io. After
# this, boxes pull the CI-published image (auto-update.sh), build-fallback only.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# System tools the collector calls out to.
# - lldpd: LLDP/CDP listener (provides lldpcli)
# - arp-scan: L2 sweep
# - nmap: -sn host discovery
# - tshark: control-plane capture
# - iproute2: ip / ss
# - iputils-ping, traceroute, dnsutils: reachability probes + ad-hoc checks
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        lldpd \
        arp-scan \
        nmap \
        tshark \
        iproute2 \
        iputils-ping \
        traceroute \
        iperf3 \
        dnsutils \
        snmp \
        ca-certificates \
        curl \
        tini \
        procps \
    && rm -rf /var/lib/apt/lists/*

# (Public speed tests use the dependency-free Cloudflare probe — see
# collector/src/collector/speedtest.py. The Ookla CLI was removed: its install
# pulled from an external apt repo at build time, which school egress filtering
# routinely blocked, leaving boxes without the binary.)

# Refresh the OUI (MAC vendor) table at build time. The `manuf` PyPI package
# bundles a years-old table that leaves ~a third of real OUIs unresolved; this
# bakes a current Wireshark manuf file into the image so vendor classification
# is accurate. Build-time only — the runtime box never reaches out (air-gapped
# preference). Non-fatal: if the download fails (offline build, URL change),
# arp.py falls back to manuf's bundled table, so the image still builds.
RUN mkdir -p /usr/share/netmon \
    && (curl -fsSL --retry 3 --max-time 60 \
            -o /usr/share/netmon/manuf \
            https://www.wireshark.org/download/automated/data/manuf \
        && echo "OUI table refreshed: $(wc -l < /usr/share/netmon/manuf) entries" \
        || echo "WARN: OUI refresh failed; falling back to bundled manuf table")

# tshark needs to run as non-root in many environments, but inside this
# container we are root and capture from the host network namespace — fine.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

WORKDIR /app

# Copy source before pip install. pyproject.toml's setuptools config points at
# src/ via `packages.find where=["src"]`, so the build step needs that directory
# to exist when `pip install .` runs — copying pyproject alone fails with
# "error in 'egg_base' option: 'src' does not exist or is not a directory".
COPY pyproject.toml /app/pyproject.toml
COPY src /app/src
RUN pip install --no-cache-dir .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /var/lib/netmon/bundles /etc/netmon

# Healthcheck — runs the DB + capabilities self-checks. interval=60s gives
# the collector time to wait for postgres on boot before being marked
# unhealthy; start-period=90s prevents false-unhealthy during initial wait.
HEALTHCHECK --interval=60s --timeout=10s --start-period=90s --retries=3 \
    CMD python -m collector healthcheck >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["run"]
