"""Remote-console session client (browser-SSH, sensor side).

When the dashboard queues an `open-console` command, the check-in handler spawns
a DETACHED subprocess running this module (`python -m collector console-session`).
It dials OUT to the zero-secret tunnel broker over WSS (443), authenticates with
the one-time session token, then services allow-listed commands the operator
sends, streaming output back. Restricted-command posture: ONLY ids in
`_DIAG_COMMANDS` (read-only) or `_CONTROL_COMMANDS` (state-changing, CON-5) run —
this module is the source of truth and re-validates every id the broker forwards.
Both registries are FIXED argv (no shell, no operator input); control actions are
in-container scope only and the dashboard gates them behind a confirm + audit.

The session is bounded three ways: the broker's idle + 15-min time-box, the
dashboard kill-switch (broker drops us), and our own hard ceiling below.
"""
from __future__ import annotations

import json
import os
import subprocess
import time

import structlog

from .checkin import _CONTROL_COMMANDS, _DIAG_COMMANDS

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


def run_console_session(broker: str, token: str, sid: str) -> int:
    """Connect to the broker and service the operator's commands until it ends."""
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

    ws.settimeout(RECV_TIMEOUT_SEC)
    deadline = time.monotonic() + MAX_SESSION_SEC
    try:
        while time.monotonic() < deadline:
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
            if ftype == "cmd":
                cmd_id = str(frame.get("id") or "")
                _run_diag_stream(ws, cmd_id)
            elif ftype == "closed":
                log.info("remote console: broker closed session", sid=sid)
                break
            # hello / ready / waiting / pong are informational; ignore.
    finally:
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        log.info("remote console: session ended", sid=sid)
    return 0


def run_from_env(broker: str, sid: str) -> int:
    """Entry point for the CLI: token comes from env (kept off the process argv)."""
    token = os.environ.get("NETMON_CONSOLE_TOKEN", "")
    return run_console_session(broker, token, sid)
