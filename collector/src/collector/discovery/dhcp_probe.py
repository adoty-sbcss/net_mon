"""Active rogue-DHCP probe (DHCP-6).

The passive capture (tshark.py) only sees a DHCP server when some client happens
to ask during the 60-second window, and a quiet VLAN yields nothing at all — which
is indistinguishable from "there is no rogue". This probe ASKS: it broadcasts one
DHCPDISCOVER on the scanned interface and records every server that answers.

Two answers matter, and they are why this is the positive control the passive
data lacks:

* the district's authorized server answering proves the probe works on this
  VLAN, so a rogue that did NOT answer really was absent at that moment;
* anything else answering is a DHCP server nobody authorized, caught even on a
  VLAN where no real client asked during the capture window.

What it deliberately does NOT do:

* It never sends a REQUEST, so it never takes a lease. An OFFER may hold an
  address for a few seconds on some servers; one DISCOVER per VLAN per full scan
  (hourly) is negligible even on a nearly full scope.
* It uses the interface's OWN MAC as chaddr and Ethernet source. A random MAC
  would trip switch port-security (err-disable the sensor's port) and could be
  refused by DHCP snooping's MAC verification. The host's own DHCP client, if it
  runs on this interface, ignores the replies because the transaction id differs.
* It does not bind UDP 67/68 (the host's DHCP client may hold 68). It sends and
  receives on a raw AF_PACKET socket bound to the interface instead.

Three outcomes, reported as `status`:

* `answered`   — at least one OFFER came back; `offers` lists every one.
* `no_answer`  — the DISCOVER went out and nothing answered within the wait. NOT
  "clean": a VLAN with no DHCP helper (an infrastructure VLAN) or a full scope
  looks exactly like this.
* `error`      — the probe could not run (no raw socket, no MAC). Unmeasured.

Linux-only syscalls (AF_PACKET) are looked up at call time so the module still
imports on the Windows dev box.
"""
from __future__ import annotations

import os
import random
import select
import socket
import struct
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

ETH_P_IP = 0x0800
# sll_pkttype for a frame this host transmitted (linux/if_packet.h). The raw
# socket sees our own DISCOVER on the way out; it is not an answer.
PACKET_OUTGOING = 4

_MAGIC_COOKIE = b"\x63\x82\x53\x63"
_BOOTREQUEST = 1
_BOOTREPLY = 2
_DHCPDISCOVER = 1
_MESSAGE_TYPES = {2: "OFFER", 5: "ACK", 6: "NAK"}

# Options asked for in the DISCOVER (option 55): subnet mask, router, DNS,
# domain name, lease time, server identifier. The router and DNS a server hands
# out are what separate a server that is merely unlisted from one that is
# redirecting clients.
_PARAM_REQUEST = bytes([1, 3, 6, 15, 51, 54])

DEFAULT_WAIT_SEC = 4.0
_MAX_OFFERS = 32  # a storm of answers is itself the finding; cap what we keep


def _iface_mac(interface: str) -> bytes | None:
    """The interface's own hardware address, or None when it has none we can use."""
    try:
        text = Path(f"/sys/class/net/{interface}/address").read_text().strip()
    except OSError:
        return None
    parts = text.split(":")
    if len(parts) != 6:
        return None
    try:
        mac = bytes(int(p, 16) for p in parts)
    except ValueError:
        return None
    if mac == b"\x00" * 6:
        return None
    return mac


def _mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_discover(mac: bytes, xid: int) -> bytes:
    """A complete Ethernet frame carrying one broadcast DHCPDISCOVER.

    Exported for the tests: the byte layout is the contract with every DHCP server
    and relay on the wire, so it is pinned rather than trusted.
    """
    options = (
        bytes([53, 1, _DHCPDISCOVER])
        + bytes([55, len(_PARAM_REQUEST)]) + _PARAM_REQUEST
        + bytes([57, 2]) + struct.pack("!H", 1500)
        + bytes([255])
    )
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        _BOOTREQUEST,
        1,  # htype: Ethernet
        6,  # hlen
        0,  # hops
        xid,
        0,  # secs
        0x8000,  # flags: BROADCAST — ask servers/relays to broadcast the reply
        b"\x00" * 4,  # ciaddr
        b"\x00" * 4,  # yiaddr
        b"\x00" * 4,  # siaddr
        b"\x00" * 4,  # giaddr
        mac + b"\x00" * 10,  # chaddr
        b"\x00" * 64,  # sname
        b"\x00" * 128,  # file
    ) + _MAGIC_COOKIE + options
    # Pad to the 300-byte BOOTP minimum some relays still enforce.
    if len(bootp) < 300:
        bootp += b"\x00" * (300 - len(bootp))
    udp_len = 8 + len(bootp)
    # UDP checksum 0 = "not computed", which IPv4 permits.
    udp = struct.pack("!HHHH", 68, 67, udp_len, 0) + bootp
    total_len = 20 + len(udp)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, random.randint(0, 0xFFFF), 0, 64, 17, 0,
        b"\x00" * 4, b"\xff" * 4,
    )
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    eth = b"\xff" * 6 + mac + struct.pack("!H", ETH_P_IP)
    return eth + ip_header + udp


def _parse_options(data: bytes) -> dict[int, bytes]:
    """Parse a DHCP options area into {code: value}. Tolerates truncation."""
    out: dict[int, bytes] = {}
    i = 0
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        if len(value) < length:
            break
        out.setdefault(code, value)
        i += 2 + length
    return out


def _ip_list(value: bytes | None) -> list[str]:
    if not value:
        return []
    return [_ip_str(value[i:i + 4]) for i in range(0, len(value) - len(value) % 4, 4)]


def parse_reply(frame: bytes, xid: int) -> dict[str, Any] | None:
    """Parse one Ethernet frame; return the DHCP reply to OUR xid, else None.

    Exported for the tests. Anything that is not an IPv4/UDP 67->68 BOOTREPLY
    carrying our transaction id is not an answer to this probe and is ignored —
    including other clients' traffic and our own outgoing DISCOVER.
    """
    if len(frame) < 14 + 20 + 8 + 240:
        return None
    if struct.unpack("!H", frame[12:14])[0] != ETH_P_IP:
        return None
    ip = frame[14:]
    if ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or ip[9] != 17:
        return None
    udp = ip[ihl:]
    if len(udp) < 8:
        return None
    sport, dport = struct.unpack("!HH", udp[:4])
    if sport != 67 or dport != 68:
        return None
    bootp = udp[8:]
    if len(bootp) < 240 or bootp[0] != _BOOTREPLY:
        return None
    if struct.unpack("!I", bootp[4:8])[0] != xid:
        return None
    if bootp[236:240] != _MAGIC_COOKIE:
        return None
    opts = _parse_options(bootp[240:])
    mtype = opts.get(53)
    kind = _MESSAGE_TYPES.get(mtype[0]) if mtype else None
    if kind is None:
        return None
    server_id = opts.get(54)
    lease = opts.get(51)
    mask = opts.get(1)
    domain = opts.get(15)
    vendor = opts.get(60)
    return {
        "message_type": kind,
        # Option 54 is the server's own identity and survives relaying; it is the
        # field the dashboard matches against the authorized list.
        "server_id": _ip_str(server_id) if server_id and len(server_id) == 4 else None,
        # Where the frame physically came from. For a relayed reply these are the
        # relay's (router SVI's) addresses, not the server's.
        "src_ip": _ip_str(ip[12:16]),
        "src_mac": _mac_str(frame[6:12]),
        "relay_ip": _ip_str(bootp[24:28]) if bootp[24:28] != b"\x00" * 4 else None,
        "offered_ip": _ip_str(bootp[16:20]) if bootp[16:20] != b"\x00" * 4 else None,
        "subnet_mask": _ip_str(mask) if mask and len(mask) == 4 else None,
        "routers": _ip_list(opts.get(3)),
        "dns_servers": _ip_list(opts.get(6)),
        "lease_sec": struct.unpack("!I", lease)[0] if lease and len(lease) == 4 else None,
        "domain": domain.decode("ascii", "replace").strip("\x00") if domain else None,
        # Option 60 in a SERVER reply: "PXEClient" marks a PXE / proxyDHCP boot
        # server (SCCM/WDS/FOG), which answers with no address at all. The
        # dashboard must not read "no gateway" there as misdirecting clients.
        "vendor_class": vendor.decode("ascii", "replace").strip("\x00") if vendor else None,
    }


def is_own_discover(frame: bytes, xid: int) -> bool:
    """True if `frame` is the DISCOVER this probe sent (same xid, 68 -> 67).

    Exported for the tests. Seeing it come back through the listening socket is
    the probe's positive control: the send happened and the listener (and its
    kernel filter) can see this interface's DHCP traffic.
    """
    if len(frame) < 14 + 20 + 8 + 240:
        return False
    if struct.unpack("!H", frame[12:14])[0] != ETH_P_IP:
        return False
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[0] >> 4 != 4 or ihl < 20 or ip[9] != 17:
        return False
    udp = ip[ihl:]
    if len(udp) < 8 + 240 or struct.unpack("!HH", udp[:4]) != (68, 67):
        return False
    bootp = udp[8:]
    return bootp[0] == _BOOTREQUEST and struct.unpack("!I", bootp[4:8])[0] == xid


def probe(interface: str, wait_sec: float = DEFAULT_WAIT_SEC) -> dict[str, Any]:
    """Broadcast one DHCPDISCOVER on `interface` and collect every OFFER.

    Never raises: a probe that cannot run is reported as status `error`, because
    an unmeasured VLAN must not be mistaken for a clean one. `no_answer` is only
    reported once the listener has seen our own DISCOVER leave — without that
    positive control, silence could just as well be a listener that hears nothing.
    """
    from . import bpf

    started = time.monotonic()
    result: dict[str, Any] = {
        "interface": interface,
        "probed_at": datetime.now(UTC).isoformat(),
        "status": "error",
        "error": None,
        "client_mac": None,
        "xid": None,
        "wait_ms": None,
        "self_test_seen": False,
        "kernel_filter": False,
        "offers": [],
    }
    mac = _iface_mac(interface)
    if mac is None:
        result["error"] = "interface has no usable MAC address"
        return result
    result["client_mac"] = _mac_str(mac)

    af_packet = getattr(socket, "AF_PACKET", None)
    if af_packet is None:
        result["error"] = "raw packet sockets are not available on this platform"
        return result

    xid = int.from_bytes(os.urandom(4), "big")
    result["xid"] = f"0x{xid:08x}"
    offers: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    # Two sockets, deliberately. Linux never loops a packet socket's own
    # transmissions back to itself, and only an ETH_P_ALL socket is shown
    # outgoing frames at all — so the listener is a separate ETH_P_ALL socket,
    # and it sees the sender's DISCOVER go out as PACKET_OUTGOING.
    try:
        rx = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(0x0003))
    except OSError as exc:
        result["error"] = f"could not open a raw socket: {exc}"
        return result
    tx: socket.socket | None = None
    try:
        rx.bind((interface, 0))
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        result["kernel_filter"] = bpf.attach(rx, bpf.DHCP_SERVER_PORT)
        # Protocol 0: a send-only packet socket. Created with ETH_P_IP it would also
        # queue every IPv4 frame on the VLAN, unread, for the whole wait.
        tx = socket.socket(af_packet, socket.SOCK_RAW, 0)
        tx.bind((interface, 0))
        # The listener is bound before sending, so a fast local server's OFFER
        # cannot arrive before we are listening.
        tx.send(build_discover(mac, xid))
        deadline = time.monotonic() + max(0.5, float(wait_sec))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([rx], [], [], remaining)
            if not ready:
                break
            frame, addr = rx.recvfrom(65535)
            # addr = (ifname, proto, pkttype, hatype, hwaddr)
            if len(addr) >= 3 and addr[2] == PACKET_OUTGOING:
                if is_own_discover(frame, xid):
                    result["self_test_seen"] = True
                continue
            reply = parse_reply(frame, xid)
            if reply is None:
                continue
            key = (reply["server_id"], reply["src_mac"], reply["offered_ip"],
                   reply["message_type"])
            if key in seen:
                continue
            seen.add(key)
            if len(offers) < _MAX_OFFERS:
                offers.append(reply)
    except OSError as exc:
        result["error"] = f"probe failed: {exc}"
        result["offers"] = offers
        result["wait_ms"] = int((time.monotonic() - started) * 1000)
        return result
    finally:
        rx.close()
        if tx is not None:
            tx.close()

    result["offers"] = offers
    result["wait_ms"] = int((time.monotonic() - started) * 1000)
    if offers:
        result["status"] = "answered"
    elif result["self_test_seen"]:
        result["status"] = "no_answer"
    else:
        result["error"] = ("the DISCOVER was never seen leaving the interface, so "
                           "silence cannot be read as no server answering")
    log.info("dhcp probe", interface=interface, status=result["status"],
             self_test=result["self_test_seen"], kernel_filter=result["kernel_filter"],
             servers=sorted({o["server_id"] or o["src_ip"] for o in offers}))
    return result
