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
`mode=full` and the check-in handler passes `--mode full` to this process. In
that mode we DROP the fixed-argv allow-list and instead bridge an INTERACTIVE
PTY (`bash -i`) to the operator's terminal — base64-framed stdin/stdout/resize.
This removes the allow-list containment, so it is gated two independent ways
(mirroring the allow-list's double-validation): the sensor only spawns the PTY
when THIS process was launched with `--mode full`, and the broker only relays
shell I/O frames when the dashboard's /validate reports `mode=full`. Every frame
still flows through the broker's transcript recorder, so the whole session is
captured. The shell runs INSIDE the (privileged) collector container; genuine
host-level ops still go through the host-action.sh allow-list.

The session is bounded three ways: the broker's idle + 15-min time-box, the
dashboard kill-switch (broker drops us), and our own hard ceiling below.
"""
from __future__ import annotations

import base64
import json
import os
import select
import signal
import subprocess
import threading
import time

import structlog

from .checkin import _CONTROL_COMMANDS, _DIAG_COMMANDS, _LIVE_OPS, _run_command

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
        out = ((p.stdout or "") + (p.stderr or "")).strip()[-OUTPUT_CAP:]
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
            text = _op_result_text(cmd_id, status, result)[-OUTPUT_CAP:]
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


# Bytes read from the PTY master per chunk; ~22 KB base64, well under the broker's
# 256 KB max payload. Output framing: {type:"o", data:<base64>}.
PTY_READ_BYTES = 16384
# Coalesce burst output into fewer, larger frames: a chatty stream (e.g. `yes`,
# `journalctl -f`) would otherwise emit thousands of tiny frames and quickly hit
# the broker's per-session transcript cap, leaving a recording gap. We batch up to
# COALESCE_MAX_BYTES of immediately-available output over a COALESCE_WINDOW window
# before sending one frame. The cap keeps the base64-encoded frame well under the
# broker's 256 KB WS max-payload (128 KB raw -> ~171 KB base64). The short window
# adds no perceptible latency to interactive single-keystroke echo.
COALESCE_MAX_BYTES = 128 * 1024
COALESCE_WINDOW_SEC = 0.04


def _kill_session(sid: int) -> None:
    """SIGKILL every process in session `sid` (Linux /proc scan; best-effort).

    Used at full-shell teardown to reach children bash put in their own process
    groups via job control, which a killpg of bash's group alone would miss. A
    process that did its own setsid (a real daemon) escapes — same as plain SSH.
    No-op / silent on non-Linux or if /proc is unreadable."""
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
            # Layout: pid (comm) state ppid pgrp session ...  `comm` can contain
            # spaces/parens, so parse the fields AFTER the final ')'.
            fields = stat[stat.rindex(")") + 1 :].split()
            psid = int(fields[3])  # state, ppid, pgrp, session
        except (OSError, ValueError, IndexError):
            continue
        if psid == sid:
            try:
                os.kill(int(entry), signal.SIGKILL)
            except OSError:
                pass


class _PtyShell:
    """An interactive in-container PTY (`bash -i`) bridged to the operator (CON-7).

    Only constructed for mode=="full" sessions, AFTER the dashboard's email
    one-time-code step-up. stdin/stdout/resize are base64-framed JSON so raw
    (non-UTF-8) terminal bytes survive the JSON relay; every frame still rides the
    broker's transcript recorder. The PTY runs inside this (privileged) container,
    so this is "full shell on the sensor"; true host ops stay on host-action.sh.

    The Unix-only modules (pty/fcntl/termios/struct) are imported lazily here so
    importing this module on a non-Unix dev box (py_compile/mypy) still works.
    """

    def __init__(self, ws) -> None:
        import fcntl
        import pty
        import struct
        import termios

        self._ws = ws
        self._fcntl = fcntl
        self._termios = termios
        self._struct = struct
        self.master_fd, slave_fd = pty.openpty()

        env = dict(os.environ)
        env.setdefault("TERM", "xterm-256color")
        # Mark the environment so an operator (and any audit) can tell this is a
        # remote-console shell, and keep history out of the box's real shell file.
        env["NETMON_REMOTE_CONSOLE"] = "1"
        env["HISTFILE"] = "/dev/null"

        def _preexec() -> None:
            # New session + make the slave our controlling terminal so job control
            # and Ctrl-C/SIGINT work like a real login shell.
            os.setsid()
            try:
                fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            except OSError:
                pass

        self.proc = subprocess.Popen(  # noqa: S603,S607 — fixed argv, shell only in PTY
            ["/bin/bash", "-i"],
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            preexec_fn=_preexec,
            env=env,
            close_fds=True,
        )
        os.close(slave_fd)  # the child holds the slave; the parent only needs master
        self._stop = threading.Event()
        self._reader = threading.Thread(
            target=self._pump_out, name="console-pty-out", daemon=True
        )
        self._reader.start()
        log.info("remote console: PTY shell started", pid=self.proc.pid)

    def _pump_out(self) -> None:
        """Read PTY output and stream it to the operator until EOF/shell-exit.

        Coalesces a burst of immediately-available output into one frame so a noisy
        command can't flood the broker's transcript cap, and stops if the operator
        connection drops (a failed send means the session is going away)."""
        while not self._stop.is_set():
            try:
                data = os.read(self.master_fd, PTY_READ_BYTES)
            except OSError:
                break  # master closed (we're shutting down) or PTY went away
            if not data:
                break  # EOF — the shell exited
            # Batch any more output already waiting, up to the size/time window.
            deadline = time.monotonic() + COALESCE_WINDOW_SEC
            while len(data) < COALESCE_MAX_BYTES:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    ready, _, _ = select.select([self.master_fd], [], [], timeout)
                except OSError:
                    break
                if not ready:
                    break
                try:
                    more = os.read(self.master_fd, PTY_READ_BYTES)
                except OSError:
                    break
                if not more:
                    break
                data += more
            if not _send(
                self._ws,
                {"type": "o", "data": base64.b64encode(data).decode("ascii")},
            ):
                break  # operator/broker gone — stop streaming
        code = self.proc.poll()
        _send(self._ws, {"type": "shell-exit", "code": -1 if code is None else code})

    def write(self, data_b64: str) -> None:
        try:
            os.write(self.master_fd, base64.b64decode(data_b64))
        except Exception:  # noqa: BLE001 — never let a bad input frame kill the loop
            pass

    def resize(self, cols: int, rows: int) -> None:
        try:
            cols = max(1, min(1000, int(cols)))
            rows = max(1, min(1000, int(rows)))
            winsize = self._struct.pack("HHHH", rows, cols, 0, 0)
            self._fcntl.ioctl(self.master_fd, self._termios.TIOCSWINSZ, winsize)
        except Exception:  # noqa: BLE001
            pass

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self) -> None:
        """Tear down the shell and EVERYTHING it spawned.

        bash is the SESSION leader (setsid in _preexec). First SIGTERM→grace→SIGKILL
        bash's own process group, then SWEEP the whole session: bash's job control
        puts backgrounded/foreground children in their OWN process groups, so a
        killpg of bash's group alone misses a child that ignores SIGHUP/SIGTERM
        (`trap '' HUP TERM`, `nohup`, a `&` job). Every process bash spawned shares
        sid==bash.pid (unless it setsid'd itself — a real daemon, same caveat as
        plain SSH), so we SIGKILL every process in that session. This stops an
        orphan from lingering root-in-(privileged-)container after the audited,
        time-boxed session ends."""
        self._stop.set()
        pgid = self.proc.pid  # == process-group AND session id thanks to setsid

        def _signal_group(sig: int) -> None:
            try:
                os.killpg(pgid, sig)
            except (ProcessLookupError, OSError):
                try:
                    self.proc.send_signal(sig)
                except Exception:  # noqa: BLE001
                    pass

        _signal_group(signal.SIGTERM)
        try:
            self.proc.wait(timeout=2)
        except Exception:  # noqa: BLE001 — still alive (or wait unavailable): force-kill
            _signal_group(signal.SIGKILL)
            try:
                self.proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass
        # Sweep any session members left in their own process groups (job control).
        _kill_session(pgid)
        try:
            os.close(self.master_fd)  # unblocks the reader thread's os.read
        except Exception:  # noqa: BLE001
            pass


def run_console_session(broker: str, token: str, sid: str, mode: str = "restricted") -> int:
    """Connect to the broker and service the operator's commands until it ends.

    mode="restricted" (default): allow-listed fixed-argv commands only (the safe
    default for every session minted before CON-7). mode="full": bridge an
    interactive PTY (full-shell, CON-7) — only ever passed when the dashboard
    minted a step-up-verified `mode=full` session.
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

    # Full-shell mode (CON-7): spawn the interactive PTY now so the prompt is ready
    # the moment the operator pairs. If the PTY can't start (no bash / non-Unix),
    # report it and end — never silently fall back to the allow-list path.
    is_full = mode == "full"
    shell: _PtyShell | None = None
    if is_full:
        try:
            shell = _PtyShell(ws)
        except Exception as exc:  # noqa: BLE001
            log.warning("remote console: could not start PTY shell", sid=sid, error=str(exc))
            _send(ws, {"type": "err", "message": f"could not start shell: {exc}"})
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
                # Full-shell session: bridge PTY I/O; the fixed-argv allow-list does
                # not apply here. Ignore `cmd` frames (the shell UI sends keystrokes).
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
