"""DHCP-6 active rogue-DHCP probe: the wire format, the parser, the kernel filter,
and the three-state outcome.

The frame builder and parser are the contract with every DHCP server and relay on
the wire, so they are pinned byte-for-byte rather than trusted. The BPF programs
are hand-assembled jump tables; `bpf.run` interprets them in Python so a wrong
offset fails here instead of silently dropping every frame on the fleet.

The outcome tests drive `probe()` against a fake raw socket. The rule under test
is the positive control: `no_answer` is only reported once the listener saw the
probe's own DISCOVER leave — silence without that proof is `error`, never clean.
"""

from __future__ import annotations

import socket as real_socket
import struct
from types import SimpleNamespace

from collector.discovery import bpf, dhcp_probe

MAC = bytes.fromhex("00e04c680a1b")
XID = 0x1A2B3C4D


def _ip_checksum_ok(header: bytes) -> bool:
    return dhcp_probe._checksum(header) == 0


def _reply(
    *,
    xid: int = XID,
    msg_type: int = 2,
    server_id: str = "10.0.0.5",
    src_ip: str = "10.0.0.5",
    src_mac: bytes = bytes.fromhex("001122334455"),
    yiaddr: str = "10.0.9.77",
    giaddr: str = "0.0.0.0",
    routers: tuple[str, ...] = ("10.0.9.1",),
    dns: tuple[str, ...] = ("10.0.0.10", "10.0.0.11"),
    lease: int = 28800,
    ihl_words: int = 5,
) -> bytes:
    """A DHCP reply frame shaped like a real server's (or relay's) OFFER/ACK."""
    opts = bytes([53, 1, msg_type])
    opts += bytes([54, 4]) + real_socket.inet_aton(server_id)
    opts += bytes([1, 4]) + real_socket.inet_aton("255.255.255.0")
    if routers:
        opts += bytes([3, 4 * len(routers)]) + b"".join(real_socket.inet_aton(r) for r in routers)
    if dns:
        opts += bytes([6, 4 * len(dns)]) + b"".join(real_socket.inet_aton(d) for d in dns)
    opts += bytes([51, 4]) + struct.pack("!I", lease)
    opts += bytes([15, 7]) + b"k12.org"
    opts += bytes([255])
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2, 1, 6, 0, xid, 0, 0x8000,
        b"\x00" * 4, real_socket.inet_aton(yiaddr), b"\x00" * 4, real_socket.inet_aton(giaddr),
        MAC + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128,
    ) + b"\x63\x82\x53\x63" + opts
    udp = struct.pack("!HHHH", 67, 68, 8 + len(bootp), 0) + bootp
    options = b"\x94\x04\x00\x00" * (ihl_words - 5)  # router-alert padding
    total = 4 * ihl_words + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl_words, 0, total, 1, 0, 64, 17, 0,
                     real_socket.inet_aton(src_ip), real_socket.inet_aton("255.255.255.255"))
    ip += options
    return b"\xff" * 6 + src_mac + b"\x08\x00" + ip + udp


# --- the DISCOVER we put on the wire ----------------------------------------


def test_discover_frame_layout():
    frame = dhcp_probe.build_discover(MAC, XID)
    assert frame[:6] == b"\xff" * 6, "broadcast destination"
    assert frame[6:12] == MAC, "the interface's OWN MAC as the Ethernet source"
    assert frame[12:14] == b"\x08\x00"
    ip = frame[14:34]
    assert _ip_checksum_ok(ip)
    assert ip[9] == 17
    assert ip[12:16] == b"\x00" * 4 and ip[16:20] == b"\xff" * 4
    sport, dport, ulen = struct.unpack("!HHH", frame[34:40])
    assert (sport, dport) == (68, 67)
    bootp = frame[42:]
    assert ulen == 8 + len(bootp)
    assert len(bootp) >= 300, "BOOTP minimum that some relays still enforce"
    assert bootp[0] == 1, "BOOTREQUEST"
    assert struct.unpack("!I", bootp[4:8])[0] == XID
    assert struct.unpack("!H", bootp[10:12])[0] == 0x8000, "broadcast flag"
    assert bootp[28:34] == MAC, "chaddr is the interface MAC, not a random one"
    assert bootp[236:240] == b"\x63\x82\x53\x63"
    opts = dhcp_probe._parse_options(bootp[240:])
    assert opts[53] == b"\x01", "DISCOVER, and never a REQUEST"
    assert set(opts[55]) >= {1, 3, 6, 54}, "asks for router + DNS + server id"


def test_own_discover_is_recognized_and_only_by_xid():
    frame = dhcp_probe.build_discover(MAC, XID)
    assert dhcp_probe.is_own_discover(frame, XID)
    assert not dhcp_probe.is_own_discover(frame, XID + 1)
    assert not dhcp_probe.is_own_discover(_reply(), XID), "a reply is not our DISCOVER"


# --- parsing what comes back ---------------------------------------------------


def test_parse_direct_offer():
    r = dhcp_probe.parse_reply(_reply(), XID)
    assert r == {
        "message_type": "OFFER",
        "server_id": "10.0.0.5",
        "src_ip": "10.0.0.5",
        "src_mac": "00:11:22:33:44:55",
        "relay_ip": None,
        "offered_ip": "10.0.9.77",
        "subnet_mask": "255.255.255.0",
        "routers": ["10.0.9.1"],
        "dns_servers": ["10.0.0.10", "10.0.0.11"],
        "lease_sec": 28800,
        "domain": "k12.org",
        "vendor_class": None,
    }


def test_parse_pxe_proxydhcp_offer():
    # A PXE / proxyDHCP boot server (SCCM/WDS/FOG) answers every DISCOVER with no
    # address, no router, no DNS, and option 60 "PXEClient". The dashboard must be
    # able to tell it apart from a server handing clients a wrong gateway.
    frame = _reply(yiaddr="0.0.0.0", routers=(), dns=(), server_id="10.1.1.40",
                   src_ip="10.1.1.40")
    # splice option 60 in before the end option
    idx = frame.rindex(bytes([255]))
    frame = frame[:idx] + bytes([60, 9]) + b"PXEClient" + frame[idx:]
    r = dhcp_probe.parse_reply(frame, XID)
    assert r is not None
    assert r["offered_ip"] is None and r["routers"] == [] and r["dns_servers"] == []
    assert r["vendor_class"] == "PXEClient"


def test_parse_relayed_offer_keeps_server_identity_separate_from_the_relay():
    # A relayed reply comes FROM the router SVI; option 54 still names the real
    # server. Matching on option 54 is what keeps a legitimate relay from ever
    # looking like a rogue server.
    frame = _reply(src_ip="10.0.9.1", src_mac=bytes.fromhex("aabbccddeeff"),
                   giaddr="10.0.9.1", server_id="10.1.1.20")
    r = dhcp_probe.parse_reply(frame, XID)
    assert r is not None
    assert r["server_id"] == "10.1.1.20"
    assert r["src_ip"] == "10.0.9.1" and r["relay_ip"] == "10.0.9.1"
    assert r["src_mac"] == "aa:bb:cc:dd:ee:ff"


def test_parse_rejects_other_transactions_and_our_own_request():
    assert dhcp_probe.parse_reply(_reply(xid=XID + 1), XID) is None
    assert dhcp_probe.parse_reply(dhcp_probe.build_discover(MAC, XID), XID) is None


def test_parse_ack_and_nak_are_kept_as_answers():
    assert dhcp_probe.parse_reply(_reply(msg_type=5), XID)["message_type"] == "ACK"
    assert dhcp_probe.parse_reply(_reply(msg_type=6), XID)["message_type"] == "NAK"


def test_parse_handles_ip_options():
    r = dhcp_probe.parse_reply(_reply(ihl_words=6), XID)
    assert r is not None and r["server_id"] == "10.0.0.5"


def test_truncated_frames_never_raise():
    frame = _reply()
    # Chop inside the options area, then inside the fixed header: a malformed
    # frame on a hostile network must be skipped, never crash the scan.
    for cut in (5, 20, 60, 200, 300):
        res = dhcp_probe.parse_reply(frame[:-cut], XID)
        assert res is None or isinstance(res, dict)


# --- the kernel filter ------------------------------------------------------------


def _udp_frame(sport: int, dport: int, *, frag: bool = False) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8, 0)
    flags = 0x0001 if frag else 0
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, flags, 64, 17, 0,
                     b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    return b"\xff" * 6 + MAC + b"\x08\x00" + ip + udp


def test_dhcp_filter_accepts_replies_and_our_discover():
    assert bpf.run(bpf.DHCP_SERVER_PORT, _reply())
    assert bpf.run(bpf.DHCP_SERVER_PORT, _reply(ihl_words=6)), "variable IP header length"
    assert bpf.run(bpf.DHCP_SERVER_PORT, dhcp_probe.build_discover(MAC, XID)), (
        "our own DISCOVER must pass, or the positive control can never fire")


def test_dhcp_filter_rejects_everything_else():
    assert not bpf.run(bpf.DHCP_SERVER_PORT, _udp_frame(53, 5353))
    assert not bpf.run(bpf.DHCP_SERVER_PORT, _udp_frame(67, 68, frag=True))
    tcp = bytearray(_udp_frame(67, 68))
    tcp[14 + 9] = 6
    assert not bpf.run(bpf.DHCP_SERVER_PORT, bytes(tcp))
    arp = bytearray(_udp_frame(67, 68))
    arp[12:14] = b"\x08\x06"
    assert not bpf.run(bpf.DHCP_SERVER_PORT, bytes(arp))


def test_igmp_filter():
    igmp = bytearray(_udp_frame(1, 1))
    igmp[14 + 9] = 2
    assert bpf.run(bpf.IGMP, bytes(igmp))
    assert not bpf.run(bpf.IGMP, _udp_frame(67, 68))


# --- the three outcomes -----------------------------------------------------------


class _FakeRawSocket:
    """Stands in for AF_PACKET sockets. The receive socket replays `frames`."""

    def __init__(self, frames):
        self.frames = list(frames)
        self.sent: list[bytes] = []

    def bind(self, addr):
        pass

    def setsockopt(self, *a):
        pass

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def recvfrom(self, n):
        return self.frames.pop(0)

    def close(self):
        pass


def _patch(monkeypatch, frames, *, af_packet=True):
    rx = _FakeRawSocket(frames)
    tx = _FakeRawSocket([])
    made = []

    def factory(family, kind, proto):
        s = rx if not made else tx
        made.append(s)
        return s

    ns = SimpleNamespace(
        socket=factory,
        SOCK_RAW=real_socket.SOCK_RAW,
        SOL_SOCKET=real_socket.SOL_SOCKET,
        SO_RCVBUF=real_socket.SO_RCVBUF,
        htons=real_socket.htons,
        inet_ntoa=real_socket.inet_ntoa,
    )
    if af_packet:
        ns.AF_PACKET = 17
    monkeypatch.setattr(dhcp_probe, "socket", ns)
    monkeypatch.setattr(
        dhcp_probe, "select",
        SimpleNamespace(select=lambda r, w, x, t: (r if rx.frames else [], [], [])))
    monkeypatch.setattr(dhcp_probe, "_iface_mac", lambda iface: MAC)
    monkeypatch.setattr(dhcp_probe.os, "urandom", lambda n: XID.to_bytes(4, "big"))
    return rx, tx


def _out(frame):
    return (frame, ("eth0", 0x0800, dhcp_probe.PACKET_OUTGOING, 1, MAC))


def _in(frame):
    return (frame, ("eth0", 0x0800, 0, 1, b"\x00" * 6))


def test_answered_lists_every_server(monkeypatch):
    discover = dhcp_probe.build_discover(MAC, XID)
    rogue = _reply(server_id="192.168.0.1", src_ip="192.168.0.1",
                   src_mac=bytes.fromhex("5c628b000001"), yiaddr="192.168.0.100",
                   routers=("192.168.0.1",), dns=("192.168.0.1",))
    _, tx = _patch(monkeypatch, [_out(discover), _in(_reply()), _in(_reply()), _in(rogue)])
    res = dhcp_probe.probe("eth0", wait_sec=0.5)
    assert tx.sent, "a DISCOVER was sent"
    assert res["status"] == "answered"
    assert res["self_test_seen"] is True
    assert [o["server_id"] for o in res["offers"]] == ["10.0.0.5", "192.168.0.1"], (
        "duplicate answers from one server collapse; a second server is kept")


def test_silence_after_a_seen_discover_is_no_answer_not_clean(monkeypatch):
    _patch(monkeypatch, [_out(dhcp_probe.build_discover(MAC, XID))])
    res = dhcp_probe.probe("eth0", wait_sec=0.5)
    assert res["status"] == "no_answer"
    assert res["offers"] == []


def test_silence_without_the_positive_control_is_an_error(monkeypatch):
    _patch(monkeypatch, [])
    res = dhcp_probe.probe("eth0", wait_sec=0.5)
    assert res["status"] == "error"
    assert "never seen leaving" in res["error"]


def test_no_raw_sockets_is_an_error_not_a_result(monkeypatch):
    _patch(monkeypatch, [], af_packet=False)
    res = dhcp_probe.probe("eth0", wait_sec=0.5)
    assert res["status"] == "error"
    assert res["offers"] == []


def test_no_mac_is_an_error(monkeypatch):
    _patch(monkeypatch, [])
    monkeypatch.setattr(dhcp_probe, "_iface_mac", lambda iface: None)
    assert dhcp_probe.probe("eth0")["status"] == "error"
