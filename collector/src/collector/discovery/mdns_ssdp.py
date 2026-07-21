"""mDNS (Bonjour) + SSDP (UPnP) service discovery.

Catches the chatty service-advertising devices that barely show up in ARP/nmap:
Apple AirPrint printers / AirPlay / Apple TV, Chromecasts (DIAL), Sonos, Rokus,
smart TVs, IP cameras, DLNA/UPnP media servers. Both are multicast
service-discovery protocols, so one module covers them:

  * SSDP  — send an HTTP-over-UDP M-SEARCH to 239.255.255.250:1900 and read the
            SERVER / ST / USN / LOCATION headers off the unicast replies.
  * mDNS  — send DNS-SD PTR queries to 224.0.0.251:5353 for a set of common
            service types, decode the responses (PTR/SRV/TXT/A), and map the
            service type to a device hint.

Pure stdlib (socket + struct): no avahi daemon, no extra Python dependency.
Everything is time-bounded and best-effort — any failure yields an empty list,
never an exception that could fail the scan. Discovery is read-only beyond the
few small multicast query packets it emits.
"""
from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Multicast endpoints.
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

# mDNS service types to actively query. The first is the DNS-SD meta-query that
# asks a responder to enumerate every service type it offers; the rest are the
# high-value ones in a K-12 network so we get answers even from responders that
# ignore the meta-query.
MDNS_SERVICE_TYPES = (
    "_services._dns-sd._udp.local",   # meta: "list your service types"
    "_ipp._tcp.local",                # AirPrint / IPP printer
    "_ipps._tcp.local",               # IPP over TLS
    "_printer._tcp.local",            # LPR printer
    "_pdl-datastream._tcp.local",     # JetDirect / port 9100 printer
    "_airplay._tcp.local",            # Apple TV / AirPlay video
    "_raop._tcp.local",               # AirPlay audio (AirPort, speakers)
    "_googlecast._tcp.local",         # Chromecast / Google/Nest, cast-enabled TVs
    "_sonos._tcp.local",              # Sonos
    "_spotify-connect._tcp.local",    # Spotify Connect speakers/TVs
    "_axis-video._tcp.local",         # Axis IP cameras
    "_rtsp._tcp.local",               # streaming / many IP cameras
    "_workstation._tcp.local",        # computers advertising via avahi
    "_smb._tcp.local",                # file shares / NAS / computers
    "_afpovertcp._tcp.local",         # Apple file sharing
    "_device-info._tcp.local",        # generic device metadata
    "_http._tcp.local",               # web admin UIs (lots of IoT/printers)
)

# Service-type / SSDP-token substring -> coarse device hint. First match wins
# (order matters: more specific before generic). The hint is advisory only;
# authoritative classification is the dashboard's job on ingest.
_HINTS: tuple[tuple[str, str], ...] = (
    # Brand-specific tokens FIRST — Roku and Chromecast both advertise the
    # generic "dial-multiscreen" SSDP type, so the brand string in SERVER/USN
    # has to win over the shared protocol token below.
    ("roku", "roku"),
    ("sonos", "sonos"),
    ("_googlecast", "chromecast"),
    # Printers (unambiguous service types).
    ("_ipp", "printer"),
    ("_ipps", "printer"),
    ("_printer", "printer"),
    ("_pdl-datastream", "printer"),
    # Apple AV / network.
    ("_airplay", "apple-av"),
    ("_raop", "apple-av"),
    ("_airport", "apple-network"),
    ("_afpovertcp", "apple-host"),
    # Media / cameras.
    ("_spotify-connect", "media-player"),
    ("_axis-video", "camera"),
    ("_rtsp", "camera"),
    # Shared/generic protocol tokens (after the brand checks above).
    ("dial-multiscreen", "cast-device"),
    ("mediarenderer", "media-player"),
    ("mediaserver", "media-server"),
    ("internetgateway", "gateway"),
    ("wanconnection", "gateway"),
    ("_workstation", "computer"),
    ("_smb", "computer"),
    ("_http", "web-ui"),
)


@dataclass
class ServiceRecord:
    ip: str
    source: str  # "mdns" | "ssdp"
    hostname: str | None = None
    services: list[str] = field(default_factory=list)
    device_hint: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_row(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "source": self.source,
            "hostname": self.hostname,
            # sorted+unique for stable output
            "services": sorted(set(self.services)) or None,
            "device_hint": self.device_hint,
            "details": self.details,
        }


def _classify(tokens: list[str]) -> str | None:
    """Map a bag of lowercased service-type / SSDP tokens to a device hint."""
    blob = " ".join(t.lower() for t in tokens if t)
    for needle, hint in _HINTS:
        if needle in blob:
            return hint
    return None


# ---------------------------------------------------------------------------
# SSDP (UPnP)
# ---------------------------------------------------------------------------

_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "USER-AGENT: NetMon/1.0 UPnP/1.0\r\n"
    "\r\n"
).encode("ascii")


def _parse_ssdp(data: bytes, src_ip: str) -> ServiceRecord | None:
    """Parse one SSDP response datagram into a ServiceRecord, or None."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None
    headers: dict[str, str] = {}
    for line in text.split("\r\n")[1:]:  # skip the status line
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    if not headers:
        return None
    st = headers.get("st") or headers.get("nt") or ""
    usn = headers.get("usn") or ""
    server = headers.get("server") or ""
    location = headers.get("location") or ""
    hint = _classify([st, usn, server])
    return ServiceRecord(
        ip=src_ip,
        source="ssdp",
        hostname=None,
        services=[s for s in (st,) if s],
        device_hint=hint,
        details={k: headers[k] for k in ("server", "st", "usn", "location")
                 if headers.get(k)} | (
            {"location": location} if location else {}),
    )


def _ssdp_search(bind_ip: str, timeout: float) -> list[ServiceRecord]:
    """Send M-SEARCH and collect unicast replies for `timeout` seconds."""
    out: dict[str, ServiceRecord] = {}
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if bind_ip:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(bind_ip),
            )
            sock.bind((bind_ip, 0))
        else:
            sock.bind(("", 0))
        # UDP is lossy; send the query a few times.
        for _ in range(2):
            try:
                sock.sendto(_SSDP_MSEARCH, (SSDP_ADDR, SSDP_PORT))
            except OSError as exc:
                log.warning("ssdp send failed", error=str(exc))
                break
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                data, addr = sock.recvfrom(8192)
            except TimeoutError:
                break
            except OSError:
                break
            rec = _parse_ssdp(data, addr[0])
            if rec is None:
                continue
            prev = out.get(rec.ip)
            if prev is None:
                out[rec.ip] = rec
            else:
                prev.services = sorted(set(prev.services) | set(rec.services))
                prev.device_hint = prev.device_hint or rec.device_hint
                prev.details.update(rec.details)
    except Exception as exc:  # pragma: no cover — defensive
        raise RuntimeError(f"SSDP discovery failed on {bind_ip or 'all interfaces'}: {exc}") from exc
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return list(out.values())


# ---------------------------------------------------------------------------
# mDNS (Bonjour / DNS-SD)
# ---------------------------------------------------------------------------

_QTYPE_A = 1
_QTYPE_PTR = 12
_QTYPE_TXT = 16
_QTYPE_AAAA = 28
_QTYPE_SRV = 33


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("utf-8")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def _encode_query(names: list[str], *, unicast_response: bool) -> bytes:
    """Build one mDNS query message asking PTR for each name."""
    header = struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0)
    qclass = 0x8001 if unicast_response else 0x0001  # high bit = QU
    body = bytearray()
    for n in names:
        body += _encode_name(n)
        body += struct.pack(">HH", _QTYPE_PTR, qclass)
    return header + bytes(body)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name starting at `offset`, following compression pointers.
    Returns (name, offset_after_the_name_in_the_record_stream)."""
    labels: list[str] = []
    jumped = False
    next_offset = offset
    pos = offset
    guard = 0
    while True:
        guard += 1
        if guard > 128 or pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                next_offset = pos
            break
        if (length & 0xC0) == 0xC0:  # compression pointer
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                next_offset = pos + 2
            jumped = True
            pos = pointer
            continue
        pos += 1
        labels.append(data[pos:pos + length].decode("utf-8", errors="replace"))
        pos += length
    return ".".join(labels), next_offset


def _decode_message(data: bytes) -> list[dict[str, Any]]:
    """Decode a DNS/mDNS message into a flat list of resource records.

    Each record: {name, type, rdata}. rdata shape depends on type:
      PTR -> {"target": name}, SRV -> {"target": name, "port": int},
      TXT -> {"txt": [str, ...]}, A -> {"ip": "1.2.3.4"}.
    Questions are skipped. Malformed input yields whatever parsed so far.
    """
    records: list[dict[str, Any]] = []
    try:
        if len(data) < 12:
            return records
        _id, _flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        pos = 12
        # Skip questions.
        for _ in range(qd):
            _name, pos = _read_name(data, pos)
            pos += 4  # qtype + qclass
        total = an + ns + ar
        for _ in range(total):
            name, pos = _read_name(data, pos)
            if pos + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            rdata_end = pos + rdlen
            if rdata_end > len(data):
                break
            rec: dict[str, Any] = {"name": name, "type": rtype}
            if rtype == _QTYPE_PTR:
                target, _ = _read_name(data, pos)
                rec["target"] = target
            elif rtype == _QTYPE_SRV:
                if rdlen >= 6:
                    _prio, _weight, port = struct.unpack(">HHH", data[pos:pos + 6])
                    target, _ = _read_name(data, pos + 6)
                    rec["target"] = target
                    rec["port"] = port
            elif rtype == _QTYPE_TXT:
                txt: list[str] = []
                tp = pos
                while tp < rdata_end:
                    ln = data[tp]
                    tp += 1
                    txt.append(data[tp:tp + ln].decode("utf-8", errors="replace"))
                    tp += ln
                rec["txt"] = txt
            elif rtype == _QTYPE_A and rdlen == 4:
                rec["ip"] = socket.inet_ntoa(data[pos:pos + 4])
            pos = rdata_end
            records.append(rec)
    except Exception:  # pragma: no cover — best-effort decode
        return records
    return records


def _service_type_of(name: str) -> str | None:
    """Extract the `_svc._proto.local` service type from a record owner/target."""
    low = name.lower()
    if "._tcp.local" in low:
        idx = low.index("._tcp.local")
        # take the last underscore-label before _tcp
        head = name[:idx]
        svc = head.split(".")[-1]
        return f"{svc}._tcp.local" if svc.startswith("_") else None
    if "._udp.local" in low:
        idx = low.index("._udp.local")
        head = name[:idx]
        svc = head.split(".")[-1]
        return f"{svc}._udp.local" if svc.startswith("_") else None
    return None


def _records_to_service(records: list[dict[str, Any]], src_ip: str) -> ServiceRecord:
    """Fold one responder's decoded RRs into a single ServiceRecord."""
    services: set[str] = set()
    hostname: str | None = None
    txt_all: list[str] = []
    for r in records:
        for field_name in ("name", "target"):
            st = _service_type_of(str(r.get(field_name) or ""))
            if st:
                services.add(st)
        if r.get("type") == _QTYPE_A:
            host = str(r.get("name") or "")
            if host.lower().endswith(".local") and not host.startswith("_"):
                hostname = hostname or host[: -len(".local")]
        if r.get("type") == _QTYPE_TXT and r.get("txt"):
            txt_all.extend(r["txt"])
    hint = _classify(list(services) + txt_all)
    details: dict[str, Any] = {}
    if txt_all:
        details["txt"] = txt_all[:20]
    return ServiceRecord(
        ip=src_ip,
        source="mdns",
        hostname=hostname,
        services=sorted(services),
        device_hint=hint,
        details=details,
    )


def _mdns_browse(bind_ip: str, timeout: float,
                 service_types: tuple[str, ...] = MDNS_SERVICE_TYPES) -> list[ServiceRecord]:
    """Query the service types and collect responses for `timeout` seconds."""
    by_ip: dict[str, list[dict[str, Any]]] = {}
    sock: socket.socket | None = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if bind_ip:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_MULTICAST_IF,
                socket.inet_aton(bind_ip),
            )
        # Prefer binding 5353 + joining the group so we catch multicast replies
        # (most responders answer to the group, not unicast). Fall back to an
        # ephemeral port with the QU bit if 5353 is taken.
        unicast = False
        try:
            sock.bind(("", MDNS_PORT))
            mreq = struct.pack("=4s4s", socket.inet_aton(MDNS_ADDR),
                               socket.inet_aton(bind_ip if bind_ip else "0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            try:
                sock.close()
            except OSError:
                pass
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            if bind_ip:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_MULTICAST_IF,
                    socket.inet_aton(bind_ip),
                )
                sock.bind((bind_ip, 0))
            else:
                sock.bind(("", 0))
            unicast = True
        query = _encode_query(list(service_types), unicast_response=unicast)
        for _ in range(2):
            try:
                sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
            except OSError as exc:
                log.warning("mdns send failed", error=str(exc))
                break
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                data, addr = sock.recvfrom(9000)
            except TimeoutError:
                break
            except OSError:
                break
            recs = _decode_message(data)
            if recs:
                by_ip.setdefault(addr[0], []).extend(recs)
    except Exception as exc:  # pragma: no cover — defensive
        raise RuntimeError(f"mDNS discovery failed on {bind_ip or 'all interfaces'}: {exc}") from exc
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return [_records_to_service(recs, ip) for ip, recs in by_ip.items()]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def discover(*, bind_ip: str | None, mdns_seconds: float = 3.0,
             ssdp_seconds: float = 3.0) -> list[dict[str, Any]]:
    """Run mDNS + SSDP discovery and return merged service rows (as dicts).

    `bind_ip` is the IP of the interface to query on (the scan's interface IP);
    None binds to all interfaces. Returns one row per (ip, source).
    """
    bip = bind_ip or ""
    records: list[ServiceRecord] = []
    if ssdp_seconds > 0:
        records += _ssdp_search(bip, ssdp_seconds)
    if mdns_seconds > 0:
        records += _mdns_browse(bip, mdns_seconds)
    rows = [r.as_row() for r in records if r.ip]
    log.info("service discovery", devices=len({r["ip"] for r in rows}),
             mdns=sum(1 for r in rows if r["source"] == "mdns"),
             ssdp=sum(1 for r in rows if r["source"] == "ssdp"))
    return rows
