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
# - iputils-ping, dnsutils: ad-hoc checks
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        lldpd \
        arp-scan \
        nmap \
        tshark \
        iproute2 \
        iputils-ping \
        dnsutils \
        ca-certificates \
        tini \
        procps \
    && rm -rf /var/lib/apt/lists/*

# tshark needs to run as non-root in many environments, but inside this
# container we are root and capture from the host network namespace — fine.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir .

COPY src /app/src
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /var/lib/appmon/bundles /etc/appmon

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
CMD ["run"]
