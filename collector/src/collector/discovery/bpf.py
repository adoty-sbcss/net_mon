"""Classic-BPF socket filters for the raw AF_PACKET listeners (DHCP-6, PERF-9).

A raw socket bound to an interface receives EVERY IPv4 frame the NIC passes up —
and while the tshark capture runs alongside, the NIC is promiscuous, so on a busy
VLAN that is thousands of frames a second for a Python loop that wants a handful.
A kernel-side filter keeps the receive buffer from overflowing and dropping the
one frame that mattered.

Attaching a filter is an optimisation, never a dependency: `attach` returns False
on any failure and the callers still check every field in Python. And because a
WRONG filter would silently drop everything, both listeners run a positive
control through it (their own outgoing packet must come back through the filter)
instead of trusting these programs.

Programs assume an untagged Ethernet frame (ethertype at offset 12), which is
what a socket bound to a VLAN sub-interface sees.
"""
from __future__ import annotations

import ctypes
import socket
import struct

SO_ATTACH_FILTER = 26  # asm-generic/socket.h

# (code, jt, jf, k)
Program = list[tuple[int, int, int, int]]

# ip proto 2 (IGMP)
IGMP: Program = [
    (0x28, 0, 0, 12),       # ldh [12]            ethertype
    (0x15, 0, 3, 0x0800),   # jeq #IPv4           else drop
    (0x30, 0, 0, 23),       # ldb [23]            ip protocol
    (0x15, 0, 1, 2),        # jeq #IGMP           else drop
    (0x06, 0, 0, 0xFFFF),   # ret #65535          accept
    (0x06, 0, 0, 0),        # ret #0              drop
]

# udp port 67 (either direction): server replies (src 67) AND our own DISCOVER
# (dst 67), which is the probe's proof the filter and the send both worked.
DHCP_SERVER_PORT: Program = [
    (0x28, 0, 0, 12),       # 0  ldh [12]
    (0x15, 0, 10, 0x0800),  # 1  jeq #IPv4            else -> 12 drop
    (0x30, 0, 0, 23),       # 2  ldb [23]
    (0x15, 0, 8, 17),       # 3  jeq #UDP             else -> 12 drop
    (0x28, 0, 0, 20),       # 4  ldh [20]             flags + fragment offset
    (0x45, 6, 0, 0x1FFF),   # 5  jset #0x1fff         fragment -> 12 drop
    (0xB1, 0, 0, 14),       # 6  ldxb 4*([14]&0xf)    x = IP header length
    (0x48, 0, 0, 14),       # 7  ldh [x + 14]         UDP source port
    (0x15, 2, 0, 67),       # 8  jeq #67              -> 11 accept
    (0x48, 0, 0, 16),       # 9  ldh [x + 16]         UDP destination port
    (0x15, 0, 1, 67),       # 10 jeq #67              else -> 12 drop
    (0x06, 0, 0, 0xFFFF),   # 11 ret #65535           accept
    (0x06, 0, 0, 0),        # 12 ret #0               drop
]


def run(program: Program, frame: bytes) -> bool:
    """Interpret `program` against `frame` in Python — the subset of classic BPF
    used above. Exists so the tests can pin what the kernel will do with these
    exact bytes, rather than trusting hand-assembled jump offsets."""
    a = 0
    x = 0
    pc = 0
    while 0 <= pc < len(program):
        code, jt, jf, k = program[pc]
        if code == 0x28:  # ldh [k]
            if k + 2 > len(frame):
                return False
            a = struct.unpack("!H", frame[k:k + 2])[0]
        elif code == 0x30:  # ldb [k]
            if k + 1 > len(frame):
                return False
            a = frame[k]
        elif code == 0x48:  # ldh [x + k]
            off = x + k
            if off + 2 > len(frame):
                return False
            a = struct.unpack("!H", frame[off:off + 2])[0]
        elif code == 0xB1:  # ldxb 4*([k]&0xf)
            if k + 1 > len(frame):
                return False
            x = (frame[k] & 0x0F) * 4
        elif code == 0x15:  # jeq #k
            pc += 1 + (jt if a == k else jf)
            continue
        elif code == 0x45:  # jset #k
            pc += 1 + (jt if a & k else jf)
            continue
        elif code == 0x06:  # ret #k
            return k != 0
        else:
            raise ValueError(f"unsupported BPF opcode 0x{code:02x}")
        pc += 1
    return False


def attach(sock: socket.socket, program: Program) -> bool:
    """Attach `program` to a raw socket. False (and no filter) on any failure."""
    try:
        insns = b"".join(struct.pack("HBBI", c, jt, jf, k) for c, jt, jf, k in program)
        buf = ctypes.create_string_buffer(insns, len(insns))
        # struct sock_fprog { unsigned short len; struct sock_filter *filter; },
        # native alignment: 2 + 6 padding + 8 on 64-bit Linux.
        fprog = struct.pack("HL", len(program), ctypes.addressof(buf))
        sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        return True
    except (OSError, ValueError, struct.error):
        return False
