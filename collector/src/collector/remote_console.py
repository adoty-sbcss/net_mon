"""Remote-console session client (browser-SSH, sensor side).

When the dashboard queues an `open-console` command, the check-in handler spawns
a DETACHED subprocess running this module (`python -m collector console-session`).
It dials OUT to the zero-secret tunnel broker over WSS (443), authenticates with
the one-time session token, then services allow-listed commands the operator
sends, streaming output back. Restricted-command posture: only ids the sensor
re-validates run —
  - `_DIAG_COMMANDS` (read-only) + `_CONTROL_COMMANDS` (state-changing, CON-5):
    FIXED argv, no shell, no operator input; run inline, bounded to ~20s.
  - `_LIVE_OPS` (in-container operational: run-scan / upload-now / config-backup /
    collect-logs): reuse the SAME handlers the queued path uses (`_run_command`),
    run in a worker THREAD so a slow op (e.g. a full scan) doesn't block the recv
    loop's keepalive and trip the broker's idle timer.
HOST-level actions (restart/rebuild/reboot/rollback) + code `update` are NOT here:
they need the host wrapper's exit-code path and stay on the queued near-live path.
This module is the source of truth and re-validates every id the broker forwards.

FULL-SHELL mode (CON-7): when the dashboard mints a session in `mode="full"`
(after an email one-time-code step-up gate) the `open-console` command carries
`mode=full`. Full shell = the real HOST root. The container can't spawn a host
process, so the arming step (checkin._spawn_console_session) launches a host-side
PTY server (scripts/netmon-host-console.py) that runs `bash -i` ON THE HOST and
exposes it over a per-session Unix socket in the shared /var/lib/netmon bind
mount. This process (`_HostShellBridge`) only RELAYS the same base64-framed
stdin/stdout/resize frames between the broker and that socket — so the operator
UI, the broker, and its transcript recorder are unchanged, and the container
never holds a host shell itself, it just pipes bytes. It is gated the same ways
the old in-container shell was (dashboard step-up + the broker only relaying shell
frames when /validate reports mode=full), plus a one-time nonce (handed to us via
env by the arming step) that authenticates us to the host server. Every frame
still flows through the broker's transcript recorder, so the whole session is
captured.

The session is bounded three ways: the broker's idle + time-box, the dashboard
kill-switch (broker drops us), and our own hard ceiling below — and the host PTY
server enforces its own matching backstop (systemd RuntimeMaxSec + self-TTL).
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time

import structlog

from .checkin import (
    _CONTROL_COMMANDS,
    _DIAG_COMMANDS,
    _LIVE_OPS,
    _redact_secrets,
    _run_command,
)

log = structlog.get_logger(__name__)

# Hard local ceiling, slightly above the broker/dashboard ABSOLUTE max (60 min,
# the most an extend can reach — CON-6) so the server side normally ends the
# session first via a "closed" frame; this is just a backstop against a wedged
# broker connection. The real (possibly extended) deadline is driven server-side.
MAX_SESSION_SEC = 61 * 60
# recv() wakes up this often to send a keepalive ping (broker idle timer is 2m).
RECV_TIMEOUT_SEC = 30
# Mirror the check-in diagnostic bounds.
DIAG_TIMEOUT_SEC = 20
OUTPUT_CAP = 16000
CHUNK = 8000


def _send(ws, obj: dict) -> bool:
    try:
        ws.send(json.dumps(obj))
        return True
    except Exception:  # noqa: BLE001
        return False


def _run_diag_stream(ws, cmd_id: str) -> None:
    """Run an allow-listed fixed-argv command, streaming begin/out/exit frames.

    Accepts read-only diagnostics (`_DIAG_COMMANDS`) and state-changing control
    actions (`_CONTROL_COMMANDS`, CON-5); both are re-validated here against the
    fixed-argv registries — the broker's allow-list is only defense in depth.
    """
    argv = _DIAG_COMMANDS.get(cmd_id) or _CONTROL_COMMANDS.get(cmd_id)
    if argv is None:
        _send(ws, {"type": "err", "id": cmd_id, "message": f"not permitted: {cmd_id}"})
        return
    _send(ws, {"type": "begin", "id": cmd_id})
    t0 = time.monotonic()
    try:
        p = subprocess.run(
            argv, capture_output=True, text=True, timeout=DIAG_TIMEOUT_SEC, check=False
        )
        # Scrub secrets before streaming to the operator + broker transcript;
        # redact the full output first, THEN cap (same guard as checkin's diag/log
        # paths). The collect-logs op path is already covered via _run_command.
        out = _redact_secrets(((p.stdout or "") + (p.stderr or "")).strip())[-OUTPUT_CAP:]
        if not out:
            out = "(no output)"
        for i in range(0, len(out), CHUNK):
            _send(ws, {"type": "out", "id": cmd_id, "data": out[i : i + CHUNK]})
        _send(
            ws,
            {
                "type": "exit",
                "id": cmd_id,
                "code": p.returncode,
                "ms": int((time.monotonic() - t0) * 1000),
            },
        )
    except subprocess.TimeoutExpired:
        _send(ws, {"type": "err", "id": cmd_id, "message": "timed out"})
    except Exception as exc:  # noqa: BLE001
        _send(ws, {"type": "err", "id": cmd_id, "message": str(exc)})


def _op_result_text(cmd_id: str, status: str, result: dict) -> str:
    """Render a queued-command result dict as terminal-friendly text for the live
    console. Mirrors the cases `_run_command` returns so the operator sees a clear
    one-liner (or log dump for collect-logs) instead of raw JSON."""
    if not isinstance(result, dict):
        return f"{status}: {result}"
    if "error" in result:
        return f"FAILED: {result['error']}"
    if cmd_id == "run-scan":
        return f"scan started — scan_id {result.get('scan_id', '?')}"
    if cmd_id == "upload-now":
        return f"upload: {result.get('status', status)}"
    if cmd_id == "config-backup":
        return f"config backup uploaded → {result.get('remote', '?')}"
    if cmd_id == "collect-logs":
        # result is {filename: contents, ...}
        return "\n".join(f"=== {k} ===\n{v}" for k, v in result.items()) or "(no logs)"
    return json.dumps(result, default=str)


def _run_op_async(ws, cmd_id: str) -> None:
    """Run an in-container operational command (run-scan / upload-now / etc.) in a
    worker thread, streaming begin/out/exit. Threaded so the recv loop keeps
    pinging the broker while a slow op runs (websocket-client send is thread-safe
    with enable_multithread=True)."""

    def worker() -> None:
        _send(ws, {"type": "begin", "id": cmd_id})
        t0 = time.monotonic()
        try:
            status, result = _run_command(cmd_id)
            # Scrub secrets before streaming to the operator + the broker's
            # PERSISTENT transcript — an op's error/success value can echo
            # credential-shaped text back at us. Redact the full text first, THEN
            # cap: the same guard the diag path applies. NOTE this masks what
            # _redact_secrets knows (KEY=secret / Bearer <token>); a blob SAS
            # `?sig=` param or an sftp://user:pass@host URL is NOT matched by its
            # key list — closing those means widening the shared regex in checkin.
            text = _redact_secrets(_op_result_text(cmd_id, status, result))[-OUTPUT_CAP:]
            for i in range(0, len(text), CHUNK):
                _send(ws, {"type": "out", "id": cmd_id, "data": text[i : i + CHUNK]})
            _send(
                ws,
                {
                    "type": "exit",
                    "id": cmd_id,
                    "code": 0 if status in ("done", "scheduled") else 1,
                    "ms": int((time.monotonic() - t0) * 1000),
                },
            )
        except Exception as exc:  # noqa: BLE001
            _send(ws, {"type": "err", "id": cmd_id, "message": str(exc)})

    threading.Thread(target=worker, name=f"console-op-{cmd_id}", daemon=True).start()


# Where the host-side PTY server (scripts/netmon-host-console.py) listens. The
# path is identical host+container thanks to the /var/lib/netmon:/var/lib/netmon
# bind mount, so this AF_UNIX socket is reachable from here.
HOST_CONSOLE_SOCK_DIR = "/var/lib/netmon"
# How long to wait for the host poll (≤30s cadence) to arm + start the server
# before we give up and fail closed. Generous enough to cover one full poll cycle
# plus the server's socket setup.
HOST_CONNECT_TIMEOUT_SEC = 45
# Read chunk for the host socket; frames are newline-delimited JSON.
SOCK_READ_BYTES = 65536


class _HostShellBridge:
    """Bridge the operator's full-shell session to a HOST root PTY (CON-7).

    The container can't spawn a host process, so scripts/netmon-host-console.py
    runs a `bash -i` PTY on the HOST and exposes it over a per-session Unix socket
    in the shared /var/lib/netmon bind mount, speaking the SAME newline-delimited
    JSON frames the broker uses ({i,resize,closed} in; {o,shell-exit} out). This
    bridge just relays frames broker<->socket, so the operator UI, the broker, and
    its transcript recorder are unchanged — and the container never holds a host
    shell itself, it only pipes bytes. Authenticated to the server by a one-time
    nonce (handed to us via env by the arming step) so a stray in-container
    process can't grab the socket. Exposes the same write/resize/alive/close
    interface the session loop used for the old in-container PTY.
    """

    def __init__(self, ws, sid: str, nonce: str) -> None:
        import socket

        self._ws = ws
        self._buf = b""
        self._exited = False
        self._send_lock = threading.Lock()
        path = f"{HOST_CONSOLE_SOCK_DIR}/host-console-{sid}.sock"

        # Retry: the host poll arms + starts the server within its ~30s cadence,
        # so the socket appears shortly after this session process starts.
        deadline = time.monotonic() + HOST_CONNECT_TIMEOUT_SEC
        last_err: Exception | None = None
        self._sock: socket.socket | None = None
        while time.monotonic() < deadline:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(path)
                self._sock = s
                break
            except OSError as exc:
                last_err = exc
                time.sleep(0.5)
        if self._sock is None:
            raise RuntimeError(f"host shell server not ready at {path}: {last_err}")

        # Handshake FIRST: prove we're the intended session before the server
        # attaches bash. A server that gets a bad/absent nonce closes on us.
        self._send_sock({"type": "hello", "nonce": nonce})
        self._reader = threading.Thread(
            target=self._pump_from_host, name="console-host-in", daemon=True
        )
        self._reader.start()
        log.info("remote console: host shell bridge connected", sid=sid)

    def _send_sock(self, obj: dict) -> None:
        try:
            with self._send_lock:
                if self._sock is not None:
                    self._sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))
        except OSError:
            self._exited = True

    def _pump_from_host(self) -> None:
        """Relay host->operator frames (o / shell-exit) verbatim to the broker."""
        sock = self._sock
        if sock is None:  # constructed only after a successful connect; guard anyway
            return
        while True:
            try:
                chunk = sock.recv(SOCK_READ_BYTES)
            except OSError:
                break
            if not chunk:
                break  # server closed the socket
            self._buf += chunk
            while b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    frame = json.loads(line.decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001
                    continue
                if frame.get("type") == "shell-exit":
                    self._exited = True
                if not _send(self._ws, frame):  # operator/broker gone
                    self._exited = True
                    return
        # Socket closed without an explicit shell-exit — synthesize one so the
        # session loop ends and the operator's terminal shows the shell closed.
        if not self._exited:
            _send(self._ws, {"type": "shell-exit", "code": -1})
        self._exited = True

    def write(self, data_b64: str) -> None:
        self._send_sock({"type": "i", "data": data_b64})

    def resize(self, cols: int, rows: int) -> None:
        self._send_sock({"type": "resize", "cols": cols, "rows": rows})

    def alive(self) -> bool:
        return not self._exited and self._reader.is_alive()

    def close(self) -> None:
        """Tell the host server to tear down bash, then drop the socket.

        The server owns the PTY + its process-group/session teardown (it SIGKILLs
        the whole bash session, mirroring the old in-container path), so a clean
        `closed` frame is enough; closing the socket is the belt-and-suspenders
        signal (the server also exits on socket EOF)."""
        self._send_sock({"type": "closed"})
        try:
            with self._send_lock:
                if self._sock is not None:
                    self._sock.close()
        except OSError:
            pass


def run_console_session(broker: str, token: str, sid: str, mode: str = "restricted") -> int:
    """Connect to the broker and service the operator's commands until it ends.

    mode="restricted" (default): allow-listed fixed-argv commands only (the safe
    default for every session minted before CON-7). mode="full": bridge an
    interactive HOST-root PTY (full-shell, CON-7) — only ever passed when the
    dashboard minted a step-up-verified `mode=full` session.
    """
    try:
        import websocket  # websocket-client (synchronous)
    except Exception as exc:  # noqa: BLE001
        log.warning("remote console: websocket-client unavailable", error=str(exc))
        return 1
    if not broker or not token or not sid:
        log.warning("remote console: missing broker/token/sid")
        return 2

    url = f"{broker}?role=sensor&token={token}&sid={sid}"
    log.info("remote console: dialing broker", sid=sid)
    try:
        ws = websocket.create_connection(url, timeout=20, enable_multithread=True)
    except Exception as exc:  # noqa: BLE001
        log.warning("remote console: connect failed", sid=sid, error=str(exc))
        return 3

    # Full-shell mode (CON-7): attach to the host-side PTY server now so the prompt
    # is ready the moment the operator pairs. Full shell targets the HOST root via
    # a bridge (see _HostShellBridge). If it can't attach (server never armed,
    # non-Unix), report it and end — never silently fall back to a container path.
    is_full = mode == "full"
    shell: _HostShellBridge | None = None
    if is_full:
        nonce = os.environ.get("NETMON_CONSOLE_HOST_NONCE", "")
        try:
            shell = _HostShellBridge(ws, sid, nonce)
        except Exception as exc:  # noqa: BLE001
            log.warning("remote console: could not start host shell", sid=sid, error=str(exc))
            _send(ws, {"type": "err", "message": f"could not start host shell: {exc}"})
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
            return 4

    ws.settimeout(RECV_TIMEOUT_SEC)
    deadline = time.monotonic() + MAX_SESSION_SEC
    try:
        while time.monotonic() < deadline:
            if shell is not None and not shell.alive():
                log.info("remote console: shell exited", sid=sid)
                break
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                try:
                    ws.ping()  # keepalive; resets the broker idle timer
                    continue
                except Exception:  # noqa: BLE001
                    break
            except Exception:  # noqa: BLE001
                break
            if not raw:
                break
            try:
                frame = json.loads(raw if isinstance(raw, str) else raw.decode())
            except Exception:  # noqa: BLE001
                continue
            ftype = frame.get("type")
            if is_full:
                # Full-shell session: bridge PTY I/O to the host server; the
                # fixed-argv allow-list does not apply. Ignore `cmd` frames.
                if shell is None:
                    continue
                if ftype == "i":
                    shell.write(str(frame.get("data") or ""))
                elif ftype == "resize":
                    shell.resize(frame.get("cols") or 80, frame.get("rows") or 24)
                elif ftype == "closed":
                    log.info("remote console: broker closed session", sid=sid)
                    break
                # hello / ready / waiting / pong / cmd are ignored in shell mode.
            elif ftype == "cmd":
                cmd_id = str(frame.get("id") or "")
                if cmd_id in _LIVE_OPS:
                    _run_op_async(ws, cmd_id)  # threaded: long ops don't block recv
                else:
                    _run_diag_stream(ws, cmd_id)  # fast fixed-argv, inline
            elif ftype == "closed":
                log.info("remote console: broker closed session", sid=sid)
                break
            # hello / ready / waiting / pong are informational; ignore.
    finally:
        if shell is not None:
            shell.close()
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        log.info("remote console: session ended", sid=sid)
    return 0


def run_from_env(broker: str, sid: str, mode: str = "restricted") -> int:
    """Entry point for the CLI: token comes from env (kept off the process argv)."""
    token = os.environ.get("NETMON_CONSOLE_TOKEN", "")
    return run_console_session(broker, token, sid, mode=mode)
