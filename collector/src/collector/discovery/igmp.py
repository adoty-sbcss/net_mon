"""IGMP querier + multicast-group listener (PERF-9).

Why this exists: school paging, bell and PA systems stream audio over multicast.
On a switch with IGMP snooping turned on, a multicast stream only reaches the
ports whose hosts have reported membership — and hosts only keep reporting when
something on the VLAN sends IGMP queries (the "querier", normally the router or
a switch configured as snooping querier). With snooping on and NO querier, the
switch's membership table ages out a few minutes after a stream starts and the
audio stops mid-announcement. It is the classic "paging works, then cuts out"
fault, and it is invisible to every other probe this sensor runs.

What this does: listen passively on one interface for IGMP for a window longer
than a query interval, and report who sent queries (and which IGMP version),
plus any group memberships heard.

Three outcomes, reported as `status`:

* `querier_seen` — at least one general or group query was heard.
* `none_heard`   — the listener ran for at least MIN_WINDOW_SEC AND its positive
  control passed, and no query arrived. Stated as "none heard", not "none
  exists": a switch can also filter IGMP towards a host port.
* `unavailable`  — the listener could not run, did not run long enough, or its
  positive control failed. Unmeasured, never clean.

POSITIVE CONTROL. A kernel filter with a wrong jump offset, or a socket that
hears nothing, would report `none_heard` on every VLAN of the fleet. So at start
the listener joins a random administratively-scoped group (239.255.x.y) on the
interface; the kernel then sends an unsolicited membership report, which the
listener must see leaving. It leaves the group at the end. The kernel's join
report (plus its standard retransmission) and the leave are the only packets
this module ever causes.

Groups: membership reports are sent towards routers, so with snooping on they
are usually NOT flooded to the sensor's port. `groups` is therefore a partial,
lower-bound view — present groups are real, absent ones prove nothing.

Linux-only syscalls are resolved at call time so the module imports on Windows.
"""
from __future__ import annotations

import os
import select
import socket
import struct
import threading
import time
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger(__name__)

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_ALLMULTI = 2

# RFC 2236/3376 default Query Interval is 125 s. A window shorter than that can
# miss a healthy querier's next query, so "none heard" needs at least this long.
MIN_WINDOW_SEC = 130
DEFAULT_WINDOW_SEC = 150

_QUERY = 0x11
_V1_REPORT = 0x12
_V2_REPORT = 0x16
_V2_LEAVE = 0x17
_V3_REPORT = 0x22


def _decode_time_code(code: int) -> float:
    """IGMPv3 Max Resp Code / QQIC encoding (RFC 3376 4.1.1 / 4.1.7): values
    below 128 are literal; above, a 3-bit exponent and 4-bit mantissa."""
    if code < 128:
        return float(code)
    exp = (code >> 4) & 0x07
    mant = code & 0x0F
    return float((mant | 0x10) << (exp + 3))


def parse_igmp(frame: bytes) -> dict[str, Any] | None:
    """Parse one Ethernet frame carrying IGMP. Exported for the tests.

    Returns {kind, src_ip, src_mac, ...} or None when the frame is not IGMP.
    """
    if len(frame) < 14 + 20 + 8:
        return None
    if struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    ip = frame[14:]
    if ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or ip[9] != 2:
        return None
    total_len = struct.unpack("!H", ip[2:4])[0]
    igmp = ip[ihl:max(ihl, min(total_len, len(ip)))]
    if len(igmp) < 8:
        return None
    src_ip = socket.inet_ntoa(ip[12:16])
    src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
    kind = igmp[0]
    out: dict[str, Any] = {"src_ip": src_ip, "src_mac": src_mac}
    if kind == _QUERY:
        group = socket.inet_ntoa(igmp[4:8])
        out["kind"] = "query"
        out["general"] = group == "0.0.0.0"
        out["group"] = None if out["general"] else group
        if len(igmp) >= 12:
            out["version"] = 3
            out["max_resp_ms"] = int(_decode_time_code(igmp[1]) * 100)
            out["qqi_sec"] = int(_decode_time_code(igmp[9]))
            out["robustness"] = igmp[8] & 0x07 or None
        else:
            out["version"] = 1 if igmp[1] == 0 else 2
            out["max_resp_ms"] = igmp[1] * 100 if igmp[1] else None
            out["qqi_sec"] = None
            out["robustness"] = None
        return out
    if kind in (_V1_REPORT, _V2_REPORT):
        out["kind"] = "report"
        out["version"] = 1 if kind == _V1_REPORT else 2
        out["groups"] = [socket.inet_ntoa(igmp[4:8])]
        return out
    if kind == _V2_LEAVE:
        out["kind"] = "leave"
        out["version"] = 2
        out["groups"] = [socket.inet_ntoa(igmp[4:8])]
        return out
    if kind == _V3_REPORT:
        out["kind"] = "report"
        out["version"] = 3
        count = struct.unpack("!H", igmp[6:8])[0]
        groups: list[str] = []
        i = 8
        for _ in range(count):
            if i + 8 > len(igmp):
                break
            aux_len = igmp[i + 1]
            nsrc = struct.unpack("!H", igmp[i + 2:i + 4])[0]
            groups.append(socket.inet_ntoa(igmp[i + 4:i + 8]))
            i += 8 + 4 * nsrc + 4 * aux_len
        out["groups"] = groups
        return out
    return None


class IgmpListener:
    """Listen for IGMP on one interface in a background thread.

    start() returns immediately; result() waits (bounded) for the window to finish
    and returns the summary. stop() ends it early, e.g. when the scan fails.
    """

    def __init__(self, interface: str, window_sec: int = DEFAULT_WINDOW_SEC) -> None:
        self.interface = interface
        self.window_sec = max(1, int(window_sec))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at: float | None = None
        self._listened_sec = 0.0
        self._error: str | None = None
        self._kernel_filter = False
        self._self_test_group: str | None = None
        self._self_test_seen = False
        self._queriers: dict[tuple[str, str], dict[str, Any]] = {}
        self._groups: dict[str, dict[str, Any]] = {}
        self._reports_seen = 0
        self._leaves_seen = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._run, name=f"igmp-{self.interface}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def result(self, extra_wait_sec: float = 5.0) -> dict[str, Any]:
        """Wait for the window to elapse (plus a small margin) and summarize."""
        if self._thread is not None and self._started_at is not None:
            remaining = self.window_sec - (time.monotonic() - self._started_at)
            self._thread.join(timeout=max(0.0, remaining) + extra_wait_sec)
            if self._thread.is_alive():
                self._stop.set()
                self._thread.join(timeout=5)
        return self.summary()

    # -- capture -----------------------------------------------------------

    def _run(self) -> None:
        from . import bpf

        af_packet = getattr(socket, "AF_PACKET", None)
        if af_packet is None:
            self._error = "raw packet sockets are not available on this platform"
            return
        try:
            sock = socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except OSError as exc:
            self._error = f"could not open a raw socket: {exc}"
            return
        joiner: socket.socket | None = None
        mreqn: bytes | None = None
        begun = time.monotonic()
        try:
            sock.bind((self.interface, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            self._kernel_filter = bpf.attach(sock, bpf.IGMP)
            ifindex = socket.if_nametoindex(self.interface)
            # Receive multicast frames for groups this host has not joined (other
            # hosts' reports) without putting the NIC into full promiscuous mode.
            # Best-effort, and undone automatically when the socket closes.
            try:
                sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                                struct.pack("iHH8s", ifindex, PACKET_MR_ALLMULTI, 0, b""))
            except OSError:
                pass
            # Positive control: a fresh group join makes the kernel send an
            # unsolicited membership report, which this socket must see leave.
            r = os.urandom(2)
            self._self_test_group = f"239.255.{r[0]}.{max(1, r[1])}"
            joiner = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            mreqn = (socket.inet_aton(self._self_test_group)
                     + socket.inet_aton("0.0.0.0")
                     + struct.pack("i", ifindex))
            try:
                joiner.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreqn)
            except OSError as exc:
                self._error = f"could not join the self-test group: {exc}"
                mreqn = None
            deadline = begun + self.window_sec
            while not self._stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                ready, _, _ = select.select([sock], [], [], min(remaining, 1.0))
                if not ready:
                    continue
                frame, addr = sock.recvfrom(65535)
                self._handle(frame, addr)
        except OSError as exc:
            self._error = f"listener failed: {exc}"
        finally:
            self._listened_sec = time.monotonic() - begun
            if joiner is not None:
                if mreqn is not None:
                    try:
                        joiner.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreqn)
                    except OSError:
                        pass
                joiner.close()
            sock.close()

    def _handle(self, frame: bytes, addr: Any) -> None:
        parsed = parse_igmp(frame)
        if parsed is None:
            return
        outgoing = isinstance(addr, tuple) and len(addr) >= 3 and addr[2] == PACKET_OUTGOING
        if outgoing:
            # Only our own traffic can be outgoing. The self-test report is the
            # one we are waiting for; the kernel's answers to real queries are
            # not other hosts' memberships and are not counted as such.
            if parsed["kind"] == "report" and self._self_test_group in parsed.get("groups", []):
                self._self_test_seen = True
            return
        now = datetime.now(UTC).isoformat()
        if parsed["kind"] == "query":
            key = (parsed["src_ip"], parsed["src_mac"])
            q = self._queriers.get(key)
            if q is None:
                q = {
                    "ip": parsed["src_ip"],
                    "mac": parsed["src_mac"],
                    "version": parsed["version"],
                    "general_queries": 0,
                    "group_queries": 0,
                    "max_resp_ms": parsed["max_resp_ms"],
                    "qqi_sec": parsed["qqi_sec"],
                    "robustness": parsed["robustness"],
                    "first_seen": now,
                    "last_seen": now,
                }
                self._queriers[key] = q
            q["last_seen"] = now
            q["version"] = parsed["version"]
            if parsed["general"]:
                q["general_queries"] += 1
            else:
                q["group_queries"] += 1
            return
        if parsed["kind"] == "report":
            self._reports_seen += 1
        else:
            self._leaves_seen += 1
        for g in parsed.get("groups", []):
            if g == self._self_test_group:
                continue
            e = self._groups.setdefault(g, {"group": g, "versions": set(), "reporters": set()})
            e["versions"].add(parsed["version"])
            e["reporters"].add(parsed["src_ip"])

    # -- summary -----------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        queriers = sorted(self._queriers.values(), key=lambda q: q["ip"])
        groups = [
            {"group": g["group"], "versions": sorted(g["versions"]),
             "reporters": len(g["reporters"])}
            for g in sorted(self._groups.values(), key=lambda e: e["group"])
        ][:200]
        listened = round(self._listened_sec, 1)
        reason: str | None = self._error
        if queriers:
            status = "querier_seen"
        elif self._error:
            status = "unavailable"
        elif not self._self_test_seen:
            status = "unavailable"
            reason = ("positive control failed: the listener never saw this sensor's "
                      "own membership report, so silence proves nothing")
        elif listened < MIN_WINDOW_SEC:
            status = "unavailable"
            reason = (f"listened for {listened:.0f}s, shorter than one default query "
                      f"interval ({MIN_WINDOW_SEC}s)")
        else:
            status = "none_heard"
        return {
            "interface": self.interface,
            "status": status,
            "reason": reason,
            "window_sec": self.window_sec,
            "listened_sec": listened,
            "self_test_seen": self._self_test_seen,
            "kernel_filter": self._kernel_filter,
            "queriers": queriers,
            "groups": groups,
            "reports_seen": self._reports_seen,
            "leaves_seen": self._leaves_seen,
        }
