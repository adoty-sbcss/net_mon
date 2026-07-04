#!/usr/bin/env python3
"""netmon-host-console.py — host-side PTY server for the CON-7 full (HOST root) shell.

Launched ON THE HOST by netmon-console-poll.sh (via `sudo systemd-run`) when the
in-container console poll claims a `mode=full` session. It runs `bash -i` as HOST
root and exposes it over a per-session Unix socket in the shared /var/lib/netmon
bind mount. The in-container console-session process (remote_console._HostShellBridge)
connects and relays the SAME base64-framed {i,resize,closed} / {o,shell-exit} JSON
frames the broker uses — so "Full shell" in the dashboard is the real host, not the
collector container, with the operator UI / broker / transcript recorder unchanged.

Security posture (preserves the existing console invariants):
  * stdlib only; a LOCAL Unix socket (no network listener — outbound-only holds).
  * 0600 socket; a one-time nonce (env NETMON_HOST_CONSOLE_NONCE, matched to the
    arming step) MUST be presented before bash is attached — a stray in-container
    process can't grab the shell.
  * no shell history (HISTFILE=/dev/null), marked NETMON_REMOTE_CONSOLE=1.
  * hard self-TTL backstop (systemd RuntimeMaxSec is the outer guard); on teardown
    the whole bash SESSION is SIGKILLed so nothing lingers root after the session.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hmac
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time

SOCK_DIR = "/var/lib/netmon"
# Match the container bridge's MAX_SESSION_SEC (61 min) as a self-backstop; the
# systemd RuntimeMaxSec and the dashboard/broker time-box normally end it first.
MAX_SESSION_SEC = 61 * 60
ACCEPT_TIMEOUT_SEC = 60   # if the container never connects, don't linger
HANDSHAKE_TIMEOUT_SEC = 10
PTY_READ_BYTES = 16384
COALESCE_MAX_BYTES = 128 * 1024
COALESCE_WINDOW_SEC = 0.04


def _kill_session(sid_pid: int) -> None:
    """SIGKILL every process in session `sid_pid` (Linux /proc scan; best-effort).

    bash's job control puts children in their own process groups, so a killpg of
    bash's group alone misses a child that ignores SIGHUP/SIGTERM. Every process
    bash spawned shares session==bash.pid (unless it setsid'd itself — a real
    daemon, same caveat as plain SSH), so kill the whole session."""
    try:
        entries = os.listdir("/proc")
    except OSError:
        return
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="ascii", errors="replace") as fh:
                stat = fh.read()
            # `comm` can contain spaces/parens — parse fields AFTER the final ')'.
            fields = stat[stat.rindex(")") + 1 :].split()
            psid = int(fields[3])  # state, ppid, pgrp, session
        except (OSError, ValueError, IndexError):
            continue
        if psid == sid_pid:
            try:
                os.kill(int(entry), signal.SIGKILL)
            except OSError:
                pass


class _Framer:
    """Newline-delimited JSON frames over a stream socket (mirrors the broker's)."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = b""

    def send(self, obj: dict) -> bool:
        try:
            self._sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))
            return True
        except OSError:
            return False

    def frames(self):
        while True:
            try:
                chunk = self._sock.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            self._buf += chunk
            while b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    yield json.loads(line.decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001 — skip a garbled frame, keep serving
                    continue


def _spawn_bash() -> tuple[subprocess.Popen, int]:
    """Open a PTY and start `bash -i` as this (root) process. Returns (proc, master_fd)."""
    import pty  # local import: Unix-only, and only needed once a client authed

    master_fd, slave_fd = pty.openpty()
    env = dict(os.environ)
    env.setdefault("TERM", "xterm-256color")
    env["NETMON_REMOTE_CONSOLE"] = "1"
    env["HISTFILE"] = "/dev/null"
    env.pop("NETMON_HOST_CONSOLE_NONCE", None)  # don't leak the nonce into the shell

    def _preexec() -> None:
        os.setsid()
        try:
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
        except OSError:
            pass

    proc = subprocess.Popen(  # noqa: S603 — fixed argv; the shell is the point here
        ["/bin/bash", "-i"],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        preexec_fn=_preexec,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)  # child holds the slave; we only need the master
    return proc, master_fd


def _teardown(proc: subprocess.Popen, master_fd: int) -> None:
    """SIGTERM→SIGKILL bash's process group, then sweep the whole session."""
    pgid = proc.pid  # == process-group AND session id (setsid in _preexec)
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except OSError:
            try:
                proc.send_signal(sig)
            except Exception:  # noqa: BLE001
                pass
        try:
            proc.wait(timeout=2)
            break
        except Exception:  # noqa: BLE001 — still alive; escalate to SIGKILL
            continue
    _kill_session(pgid)
    try:
        os.close(master_fd)
    except OSError:
        pass


def _serve(conn: socket.socket, nonce: str) -> None:
    framer = _Framer(conn)

    # Nonce handshake BEFORE attaching bash: the first frame must be a hello whose
    # nonce matches the one the arming step handed the container. Anything else
    # (wrong nonce, no frame within the timeout, a different type) → refuse.
    conn.settimeout(HANDSHAKE_TIMEOUT_SEC)
    authed = False
    for frame in framer.frames():
        if frame.get("type") == "hello" and nonce and hmac.compare_digest(
            str(frame.get("nonce") or ""), nonce
        ):
            authed = True
        break
    conn.settimeout(None)
    if not authed:
        framer.send({"type": "shell-exit", "code": -1})
        return

    proc, master_fd = _spawn_bash()
    stop = threading.Event()
    deadline = time.monotonic() + MAX_SESSION_SEC

    def pump_out() -> None:
        while not stop.is_set():
            try:
                data = os.read(master_fd, PTY_READ_BYTES)
            except OSError:
                break
            if not data:
                break  # EOF — bash exited
            # Coalesce a burst so a chatty command doesn't flood the transcript cap.
            end = time.monotonic() + COALESCE_WINDOW_SEC
            while len(data) < COALESCE_MAX_BYTES:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    ready, _, _ = select.select([master_fd], [], [], remaining)
                except OSError:
                    break
                if not ready:
                    break
                try:
                    more = os.read(master_fd, PTY_READ_BYTES)
                except OSError:
                    break
                if not more:
                    break
                data += more
            if not framer.send({"type": "o", "data": base64.b64encode(data).decode("ascii")}):
                break  # container/broker gone
        code = proc.poll()
        framer.send({"type": "shell-exit", "code": -1 if code is None else code})

    reader = threading.Thread(target=pump_out, name="host-pty-out", daemon=True)
    reader.start()

    try:
        for frame in framer.frames():
            if time.monotonic() > deadline or proc.poll() is not None:
                break
            ftype = frame.get("type")
            if ftype == "i":
                try:
                    os.write(master_fd, base64.b64decode(str(frame.get("data") or "")))
                except Exception:  # noqa: BLE001 — a bad input frame must not kill us
                    pass
            elif ftype == "resize":
                try:
                    cols = max(1, min(1000, int(frame.get("cols") or 80)))
                    rows = max(1, min(1000, int(frame.get("rows") or 24)))
                    fcntl.ioctl(
                        master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0)
                    )
                except Exception:  # noqa: BLE001
                    pass
            elif ftype == "closed":
                break
    finally:
        stop.set()
        _teardown(proc, master_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description="NetMon host-side console PTY server (CON-7).")
    parser.add_argument("--sid", required=True, help="Session id (matches the socket name).")
    args = parser.parse_args()

    nonce = os.environ.get("NETMON_HOST_CONSOLE_NONCE", "")
    if not nonce:
        print("netmon-host-console: no nonce provided; refusing to start", file=sys.stderr)
        return 2

    # Basic sid hygiene so it can only ever be a socket filename, never a path.
    sid = args.sid
    if not sid or "/" in sid or ".." in sid or len(sid) > 128:
        print("netmon-host-console: invalid sid", file=sys.stderr)
        return 2

    path = os.path.join(SOCK_DIR, f"host-console-{sid}.sock")
    try:
        os.unlink(path)  # clear a stale socket from a prior run
    except OSError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        old_umask = os.umask(0o177)  # socket created 0600; restore right after bind
        try:
            srv.bind(path)
        finally:
            os.umask(old_umask)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        srv.listen(1)
        srv.settimeout(ACCEPT_TIMEOUT_SEC)
        print(f"netmon-host-console: listening for sid={sid}", flush=True)
        try:
            conn, _ = srv.accept()
        except (socket.timeout, TimeoutError):
            print("netmon-host-console: no client connected; exiting", file=sys.stderr)
            return 0
        with conn:
            _serve(conn, nonce)
    finally:
        try:
            srv.close()
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    print(f"netmon-host-console: session ended for sid={sid}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
