"""Failure taxonomy for device SSH sessions (NCM-6).

Why this exists: "the backup failed" is useless to a district IT generalist. Each
way it can fail has a *different fix* and a *different owner* — a firewall ACL, an
SSH server that was never enabled, a password that changed, a read-only role that
was never applied to that box. Collapsing those into one error string means the
operator's first move is always a guess.

So every SSH attempt reports a STAGE and a machine-readable CODE:

    reach   → could we open a TCP session to the SSH port at all?
    ssh     → did SSH negotiate (banner, key exchange, host identity)?
    auth    → were the credentials accepted?
    authz   → is the account ALLOWED to read the configuration?
    read    → did the config come back intact?
    save    → (backup only) did redaction + storage succeed?

`auth` and `authz` are deliberately separate stages. With the least-privilege
parser-view account model, "the password works" and "the account may read the
config" are provisioned separately and fail separately — and misfiling the second
as the first sends the operator off to rotate credentials that were fine.

⚠️ SECURITY: a result NEVER carries raw exception text, an SSH banner, device
output, or a username — only a code plus structured numbers. Raw library strings
routinely embed the username and connection detail. `_scrub` in device_config.py
stays as defense-in-depth beneath this, not instead of it.

Pure + dependency-free so it is exhaustively unit-testable against real netmiko /
paramiko failure strings without opening a socket.
"""

from __future__ import annotations

import re
import socket
from typing import Any

# --- Stages, in the order they are attempted --------------------------------
STAGES = ("reach", "ssh", "auth", "authz", "read", "save")

# The whole taxonomy. Each code is stable and shared with the dashboard, which
# owns the operator-facing copy (one vocabulary, three consumers: on-demand test,
# on-demand backup, and the nightly pass).
CODES = {
    # reach — nothing answered, or something answered that isn't SSH
    "reach.ssh_timeout": "TCP connect timed out but the host answers ping",
    "reach.host_silent": "no ping, no SSH — host may be off or unreachable",
    "reach.refused": "connection refused — nothing listening on the port",
    "reach.no_route": "network reports no path to the host",
    "reach.reset": "connection opened then immediately cut off",
    # ssh — negotiation, before any credential is offered
    "ssh.not_ssh": "the port answered, but not with SSH",
    "ssh.legacy_crypto": "device only offers outdated SSH algorithms",
    "ssh.identity_changed": "host key differs from the one previously seen",
    "ssh.banner_timeout": "TCP connected but the SSH banner never arrived",
    # auth — credentials offered
    "auth.rejected": "device rejected the credentials",
    "auth.lockout_suspected": "repeated rejections; account may be locked",
    "auth.aaa_timeout": "auth service never answered (RADIUS/TACACS down?)",
    # authz — signed in, but not permitted
    "authz.no_read_access": "signed in, but the account can't read the config",
    # read — the config itself
    "read.timeout": "reading the config timed out",
    "read.empty": "empty or garbled response — platform likely wrong",
    "read.too_large": "config exceeded the size cap",
    # save — backup only
    "save.redaction_failed": "a secret survived redaction; config not stored",
    "save.upload_failed": "read and redacted, but the upload failed",
    # fallback
    "error.unclassified": "failed in a way we couldn't classify",
    "error.unsupported_platform": "no command set for this platform",
    "error.no_host": "no management address on record",
}

# --- Signature tables -------------------------------------------------------
# Matched against the LOWERCASED exception text. Order matters within each stage:
# the first match wins, so the more specific signature must come first.

_AUTHZ_MARKERS = (
    "% invalid input",
    "% permission denied",
    "% authorization failed",
    "invalid input detected",
    "command authorization failed",
    "% incomplete command",
    "insufficient privilege",
    "access denied",
    "you do not have permission",
)

_SSH_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("ssh.identity_changed", re.compile(r"host key.*(mismatch|changed|not match)|bad host key|known_hosts")),
    ("ssh.legacy_crypto", re.compile(r"no matching (key exchange|cipher|mac|host key|kex)|incompatible (ssh|version)|unable to agree")),
    # ORDER: "Error reading SSH protocol banner" is paramiko's classic
    # waited-and-got-nothing timeout — TCP connected, SSH never spoke. It must be
    # read as a banner TIMEOUT, not as "something other than SSH answered", or the
    # operator gets sent to check what's running on the port when the real answer is
    # that the device is overloaded.
    ("ssh.banner_timeout", re.compile(r"reading ssh protocol banner|timed out waiting.*banner|banner timeout")),
    ("ssh.not_ssh", re.compile(r"not a valid ssh|invalid banner|bad packet length|unsupported protocol")),
]

_AUTH_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("auth.lockout_suspected", re.compile(r"account.*(lock|disabled)|too many (failed|authentication)|max.*attempts")),
    ("auth.aaa_timeout", re.compile(r"(radius|tacacs|aaa).*(time|unreach|fail)|authentication timeout|timeout during auth")),
    ("auth.rejected", re.compile(r"authentication (failed|to device failed)|permission denied|bad password|access denied|incorrect password|login (failed|invalid)")),
]

_REACH_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("reach.refused", re.compile(r"connection refused|econnrefused|actively refused")),
    ("reach.no_route", re.compile(r"no route to host|network is unreachable|ehostunreach|enetunreach")),
    ("reach.reset", re.compile(r"connection reset|econnreset|forcibly closed")),
    ("reach.ssh_timeout", re.compile(r"timed out|timeout|etimedout|connection to .* timed-out")),
]

_READ_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("read.timeout", re.compile(r"read.*timeout|pattern.*not detected|search pattern never detected")),
    ("read.empty", re.compile(r"empty|no output|unable to determine|prompt")),
]


def _text(exc: BaseException | str) -> str:
    return (exc if isinstance(exc, str) else f"{type(exc).__name__}: {exc}").lower()


def looks_like_authz_denial(output: str | None) -> bool:
    """True when the device SIGNED US IN and then refused the command.

    This is the single most common onboarding failure — the password is right, the
    read-only role was never applied to this box — and it is the one most often
    misdiagnosed as a bad password, sending the operator to rotate credentials that
    were working fine.
    """
    if not output:
        return False
    low = output.lower()
    return any(m in low for m in _AUTHZ_MARKERS)


def classify_exception(
    exc: BaseException | str,
    *,
    ping_ok: bool | None = None,
    authenticated: bool = False,
) -> tuple[str, str]:
    """Map an SSH failure to (stage, code). Never raises.

    `ping_ok` splits the two reach timeouts, which look identical to the SSH client
    but send the operator to different buildings: a host that answers ping has SSH
    off or filtered; one that answers nothing may simply be powered off or gone from
    that address. `authenticated` says we got past the credential exchange, so a
    later failure can't be an auth problem.
    """
    text = _text(exc)
    name = type(exc).__name__.lower() if not isinstance(exc, str) else ""

    # Netmiko's typed exceptions are the strongest signal available.
    if "authentication" in name:
        for code, pat in _AUTH_SIGNATURES:
            if pat.search(text):
                return "auth", code
        return "auth", "auth.rejected"

    # Once signed in, a failure can't be about credentials.
    if not authenticated:
        for code, pat in _SSH_SIGNATURES:
            if pat.search(text):
                return "ssh", code
        for code, pat in _AUTH_SIGNATURES:
            if pat.search(text):
                return "auth", code
        for code, pat in _REACH_SIGNATURES:
            if pat.search(text):
                # A plain timeout is ambiguous until ping disambiguates it.
                if code == "reach.ssh_timeout" and ping_ok is False:
                    return "reach", "reach.host_silent"
                return "reach", code
    else:
        for code, pat in _READ_SIGNATURES:
            if pat.search(text):
                return "read", code
        if _REACH_SIGNATURES[2][1].search(text):  # reset mid-session
            return "read", "read.timeout"

    return "error", "error.unclassified"


def tcp_ping(host: str, port: int = 22, timeout: float = 3.0) -> bool:
    """Best-effort liveness probe used ONLY to split the two reach timeouts.

    Deliberately a TCP connect rather than ICMP: it needs no raw socket (so no
    elevated privileges inside the container), and a school network that filters
    ICMP — many do — would otherwise make every unreachable device report the
    broader 'nothing answered' copy. A closed port still proves the host is alive,
    because the stack refused rather than swallowing the packet.
    """
    for probe_port in (port, 443, 80):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, probe_port))
            return True
        except ConnectionRefusedError:
            return True  # something is home; it just said no
        except OSError:
            continue
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return False


def stage_ladder(failed_stage: str | None) -> dict[str, str]:
    """Per-stage pass/fail/skipped map — what the operator sees as a checklist.

    A stage after the failure is 'skipped', not 'failed': we never attempted it, and
    reporting it as failed would send the operator chasing a problem that may not
    exist.
    """
    out: dict[str, str] = {}
    hit = False
    for stage in STAGES:
        if failed_stage == stage:
            hit = True
            out[stage] = "failed"
        elif hit:
            out[stage] = "skipped"
        else:
            out[stage] = "passed"
    return out


def result_for(
    *,
    stage: str | None,
    code: str | None,
    elapsed_ms: int | None = None,
    bytes_read: int | None = None,
    ping_ok: bool | None = None,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    """Build the result payload posted back to the dashboard.

    Contains ONLY codes and numbers. No exception text, no banner, no device output,
    no username — see the security note in this module's docstring.
    """
    ok = code is None
    return {
        "ok": ok,
        "stage": None if ok else stage,
        "code": code,
        "ladder": stage_ladder(None if ok else stage),
        "elapsed_ms": elapsed_ms,
        "bytes_read": bytes_read,
        "ping_ok": ping_ok,
        "notes": notes or [],
    }
