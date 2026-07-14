"""Authoritative DHCP server intelligence (DHCP-2).

The passive DHCP view the dashboard already shows is *inferred* from OFFER/ACK
packets a sensor happened to sniff — the DHCP page itself footnotes it as "a
lower bound, not the server's authoritative lease database." This module fills
that gap: for each **authorized** DHCP server the operator has enabled active
collection on, we open a WinRM session and run the Windows **DhcpServer**
PowerShell module to pull the server's own truth —

  * scopes (subnet, range, mask, lease duration, Active/Inactive state),
  * per-scope statistics (addresses in use / free, **% utilization**, reserved),
  * scope + server **option values** (router/DNS/domain/NTP/PXE/...), which is
    what makes "misconfigured options" detectable at all,
  * failover relationships (partner, mode, state) so a broken/absent failover
    on a big scope surfaces,
  * server-wide statistics + authorization/domain-join status.

Only **Windows** servers are supported in v1 (the K-12 reality); the target
carries a `server_type` so other backends (Infoblox/Kea) can slot in later
(DHCP-7) without changing the bundle contract.

Why WinRM/PowerShell and not SNMP/WMI: Windows DHCP exposes *nothing* useful
about scopes/utilization/options over standard SNMP MIBs, and the legacy WMI
provider is thin. The DhcpServer PowerShell module (CIM-based) is the rich,
supported surface, and WinRM is the clean way to drive it from our Linux
container. Least-privilege is a domain account in the server's read-only
**"DHCP Users"** group — never Domain Admin.

Security/robustness posture (mirrors the SNMP-crawl + Wi-Fi-join modules):
  * OFF by default; targets + credentials ride a 0600 JSON file written by
    check-in from the dashboard push (never on argv, never in env).
  * Every target is isolated in try/except — an unreachable server or bad
    credential records a status/error and never crashes the poll loop.
  * Bounded by a per-server WinRM timeout AND a whole-pass wall-clock budget.
  * pywinrm is imported lazily so a box without the dep (feature off) still
    imports the collector cleanly.

Output (written to INTEL_FILE, shipped box-global in the hourly bundle as
`dhcp_intel.json`; contains NO secrets, only server config the operator owns):

    {
      "collected_at": "<iso8601 utc>",
      "servers": [
        {"server_ip", "label", "server_type", "status": "ok",
         "hostname", "is_authorized", "is_domain_joined",
         "server_stats": {...}, "failover": [...], "server_options": [...],
         "scopes": [{scope_id, name, state, start_range, end_range,
                     subnet_mask, lease_duration_sec, addresses_in_use,
                     addresses_free, percentage_in_use, reserved,
                     options: [{id, name, value: [...]}, ...]}, ...]},
        {"server_ip", "label", "status": "error", "error": "..."},
        ...
      ],
      "stats": {"targets", "ok", "errors", "elapsed_sec", "budget_exhausted"}
    }
"""
from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Target list (0600, secrets) written by checkin from the dashboard push, and
# the box-global intel artifact the bundle ships. Both live under the same
# state dir as the other pushed-config files (iperf-schedules, wifi-profiles).
TARGETS_FILE = Path("/var/lib/netmon/dhcp-targets.json")
INTEL_FILE = Path("/var/lib/netmon/dhcp_intel.json")

# Cap the remote payload we'll parse — a healthy server with hundreds of scopes
# is still well under this; a runaway output gets rejected rather than eating
# memory.
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# The PowerShell probe — one script, one JSON document, run on the server.
# ---------------------------------------------------------------------------
# We WinRM directly to the DHCP server, so the DhcpServer cmdlets run locally
# on it (no -ComputerName). Everything is coerced to strings/ints and arrays
# are forced with @(...) so Windows PowerShell 5.1's ConvertTo-Json (which
# collapses single-element arrays and defaults to depth 2) can't mangle the
# shape. A top-level try/catch emits {ok:false,error:...} so a missing module
# or denied permission comes back as clean JSON instead of a raw stack trace.
_PS_PROBE = r"""
$ErrorActionPreference = 'Stop'
function Opts($values) {
  @($values | ForEach-Object { @{ id = [int]$_.OptionId; name = "$($_.Name)"; value = @($_.Value | ForEach-Object { "$_" }) } })
}
try {
  Import-Module DhcpServer -ErrorAction Stop
  $srvStats = Get-DhcpServerv4Statistics
  $setting  = $null
  try { $setting = Get-DhcpServerSetting } catch {}
  $failover = @()
  try { $failover = @(Get-DhcpServerv4Failover -ErrorAction SilentlyContinue) } catch {}
  $serverOpts = @()
  try { $serverOpts = Opts(Get-DhcpServerv4OptionValue -ErrorAction SilentlyContinue) } catch {}
  $scopeList = @()
  foreach ($s in @(Get-DhcpServerv4Scope)) {
    $st = $null
    try { $st = Get-DhcpServerv4ScopeStatistics -ScopeId $s.ScopeId } catch {}
    $opts = @()
    try { $opts = Opts(Get-DhcpServerv4OptionValue -ScopeId $s.ScopeId -ErrorAction SilentlyContinue) } catch {}
    $scopeList += @{
      scope_id           = "$($s.ScopeId)"
      name               = "$($s.Name)"
      state              = "$($s.State)"
      start_range        = "$($s.StartRange)"
      end_range          = "$($s.EndRange)"
      subnet_mask        = "$($s.SubnetMask)"
      lease_duration_sec = [int]$s.LeaseDuration.TotalSeconds
      description        = "$($s.Description)"
      addresses_in_use   = if ($st) { [int]$st.AddressesInUse } else { $null }
      addresses_free     = if ($st) { [int]$st.AddressesFree } else { $null }
      percentage_in_use  = if ($st) { [double]$st.PercentageInUse } else { $null }
      reserved           = if ($st) { [int]$st.Reserved } else { $null }
      options            = $opts
    }
  }
  $out = @{
    ok               = $true
    hostname         = "$env:COMPUTERNAME"
    is_authorized    = if ($setting) { [bool]$setting.IsAuthorized } else { $null }
    is_domain_joined = if ($setting) { [bool]$setting.IsDomainJoined } else { $null }
    server_stats     = @{
      total_scopes        = [int]$srvStats.TotalScopes
      total_addresses     = [double]$srvStats.TotalAddresses
      addresses_in_use    = [double]$srvStats.AddressesInUse
      addresses_available = [double]$srvStats.AddressesAvailable
      percentage_in_use   = [double]$srvStats.PercentageInUse
    }
    failover = @($failover | ForEach-Object {
      @{ name = "$($_.Name)"; partner = "$($_.PartnerServer)"; mode = "$($_.Mode)";
         state = "$($_.State)"; enabled = [bool]$_.Enabled;
         scope_ids = @($_.ScopeId | ForEach-Object { "$_" }) }
    })
    server_options = $serverOpts
    scopes         = $scopeList
  }
  $out | ConvertTo-Json -Depth 6 -Compress
} catch {
  @{ ok = $false; error = "$($_.Exception.Message)" } | ConvertTo-Json -Compress
}
"""


# ---------------------------------------------------------------------------
# Per-target collection
# ---------------------------------------------------------------------------


def _collect_one(target: dict[str, Any], *, winrm_timeout: int) -> dict[str, Any]:
    """Query one DHCP server. Never raises — returns a status dict either way."""
    ip = str(target.get("server_ip") or "").strip()
    label = target.get("label")
    server_type = str(target.get("server_type") or "windows").lower()
    base = {"server_ip": ip, "label": label, "server_type": server_type}

    if not ip:
        return {**base, "status": "error", "error": "no server_ip"}
    if server_type != "windows":
        return {**base, "status": "unsupported",
                "error": f"server_type '{server_type}' not supported yet (v1 = windows)"}

    transport = str(target.get("transport") or "auto").lower()
    user = str(target.get("winrm_user") or "")
    password = str(target.get("winrm_password") or "")

    # Explicit RPC transport (DHCP-9): talk straight to the DHCP service over
    # MS-DHCPM — authorizes on the DHCP Users group ALONE, no WinRM, no WMI. The
    # escape hatch for hardened boxes that block non-admin WMI/DCOM.
    if transport == "rpc":
        return _collect_via_rpc(base, ip=ip, user=user, password=password,
                                winrm_timeout=winrm_timeout)

    try:
        import winrm  # lazy: only needed when a target is actually collected
    except Exception as exc:  # pragma: no cover — dep-missing guard
        return {**base, "status": "error", "error": f"pywinrm unavailable: {exc}"}

    port = int(target.get("winrm_port") or (5986 if target.get("use_https") else 5985))
    scheme = "https" if target.get("use_https") else "http"
    endpoint = f"{scheme}://{ip}:{port}/wsman"

    # Auto-detect (default): probe what the server actually accepts and pick NTLM
    # where it's offered, Kerberos where NTLM is disabled — the operator never has
    # to choose (DHCP-8). An explicit 'ntlm'/'kerberos' overrides the probe. On auto
    # we may also fall back to RPC below when WinRM's WMI gate denies a non-admin.
    auto_transport = transport in ("", "auto")
    if auto_transport:
        transport = _detect_transport(endpoint, winrm_timeout) or "ntlm"

    # Kerberos needs a ticket: kinit the same credential into a private ccache that
    # pywinrm's gssapi transport then uses. NTLM needs none of this.
    ccache: str | None = None
    if transport == "kerberos":
        try:
            ccache = _kinit(user, password, ip)
        except Exception as exc:  # noqa: BLE001 — surface a clean, scrubbed reason
            return {**base, "status": "error", "transport": "kerberos",
                    "error": _short(_scrub(f"Kerberos sign-in failed: {exc}", password))}

    try:
        session = winrm.Session(
            endpoint,
            auth=(user, password),
            transport=transport,
            server_cert_validation="ignore",
            operation_timeout_sec=max(5, winrm_timeout - 5),
            read_timeout_sec=winrm_timeout,
        )
        result = session.run_ps(_PS_PROBE)
    except Exception as exc:  # connection / auth / transport error
        return {**base, "status": "error", "transport": transport,
                "error": _short(_scrub(str(exc), password))}
    finally:
        if ccache:
            _cleanup_ccache(ccache)

    if getattr(result, "status_code", 1) != 0:
        err = _short(_scrub((result.std_err or b"").decode("utf-8", "replace"), password))
        return {**base, "status": "error", "transport": transport,
                "error": err or "winrm returned non-zero"}

    raw = result.std_out or b""
    if len(raw) > _MAX_OUTPUT_BYTES:
        return {**base, "status": "error", "transport": transport,
                "error": "server response too large"}
    try:
        parsed = json.loads(raw.decode("utf-8", "replace") or "{}")
    except Exception as exc:
        return {**base, "status": "error", "transport": transport,
                "error": f"unparseable server response: {exc}"}

    if not parsed.get("ok"):
        err = _short(str(parsed.get("error") or "DhcpServer probe failed"))
        # Hardened boxes let the WinRM shell in but block non-admin WMI/DCOM
        # ("Cannot connect to CIM server. Access denied"). The DHCP service's own
        # RPC has no WMI gate — auto-fall back to it, but only when the operator
        # left transport on auto (a pinned transport gets the raw WinRM error).
        if auto_transport and _is_wmi_denied(err):
            rpc_result = _collect_via_rpc(base, ip=ip, user=user,
                                          password=password, winrm_timeout=winrm_timeout)
            if rpc_result.get("status") == "ok":
                return rpc_result
        return {**base, "status": "error", "transport": transport, "error": err}

    # Merge the server's own report onto the target identity. `ok`/`error` in the
    # PS payload are control fields — drop them; keep everything else. `transport`
    # records which auth actually worked, for the dashboard status line.
    parsed.pop("ok", None)
    parsed.pop("error", None)
    return {**base, "status": "ok", "transport": transport, **parsed}


def _is_wmi_denied(err: str) -> bool:
    """True for the hardened-box signature where the WinRM shell ran but the
    DhcpServer cmdlets couldn't reach WMI/DCOM as a non-admin."""
    return "cannot connect to cim server" in (err or "").lower()


def _collect_via_rpc(
    base: dict[str, Any], *, ip: str, user: str, password: str, winrm_timeout: int
) -> dict[str, Any]:
    """DHCP intel over MS-DHCPM RPC (DHCP-9) — authorizes on the DHCP Users group
    alone, no WinRM/WMI. The escape hatch for hardened boxes that block non-admin
    WMI. Reuses the Kerberos kinit (most hardened AD shops disable NTLM); falls
    back to letting impacket try NTLM if a ticket can't be minted. Never raises."""
    try:
        from . import dhcp_rpc
    except Exception as exc:  # pragma: no cover — dep-missing guard
        return {**base, "status": "error", "transport": "rpc",
                "error": _short(f"rpc collector unavailable: {exc}")}

    ccache: str | None = None
    use_kerberos = True
    try:
        ccache = _kinit(user, password, ip)  # sets KRB5CCNAME for impacket
    except Exception:  # noqa: BLE001 — no ticket; let impacket attempt NTLM
        use_kerberos = False
    try:
        parsed = dhcp_rpc.collect(
            ip, user, password, kdc=None, use_kerberos=use_kerberos, timeout=winrm_timeout
        )
    except Exception as exc:  # noqa: BLE001 — connection / auth / bind error
        return {**base, "status": "error", "transport": "rpc",
                "error": _short(_scrub(str(exc), password))}
    finally:
        if ccache:
            _cleanup_ccache(ccache)
    parsed.pop("transport_detail", None)
    return {**base, "status": "ok", "transport": "rpc", **parsed}


# ---------------------------------------------------------------------------
# Whole-pass orchestration
# ---------------------------------------------------------------------------


def collect_all(
    targets: list[dict[str, Any]],
    *,
    winrm_timeout: int = 30,
    time_budget: int = 120,
) -> dict[str, Any]:
    """Query every target, bounded by a wall-clock budget. Never raises."""
    start = time.monotonic()
    servers: list[dict[str, Any]] = []
    budget_exhausted = False

    for target in targets:
        if time.monotonic() - start > time_budget:
            budget_exhausted = True
            servers.append({
                "server_ip": str(target.get("server_ip") or ""),
                "label": target.get("label"),
                "status": "skipped",
                "error": "time budget exhausted",
            })
            continue
        entry = _collect_one(target, winrm_timeout=winrm_timeout)
        if entry.get("status") == "ok":
            log.info("dhcp intel collected", server=entry["server_ip"],
                     scopes=len(entry.get("scopes") or []))
        else:
            log.warning("dhcp intel failed", server=entry.get("server_ip"),
                        status=entry.get("status"), error=entry.get("error"))
        servers.append(entry)

    ok = sum(1 for s in servers if s.get("status") == "ok")
    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "servers": servers,
        "stats": {
            "targets": len(targets),
            "ok": ok,
            "errors": len(servers) - ok,
            "elapsed_sec": round(time.monotonic() - start, 2),
            "budget_exhausted": budget_exhausted,
        },
    }


def collect_and_store(settings: Any) -> None:
    """Gated periodic collect for the poll loop. No-op unless the feature is on,
    targets exist, and the last artifact is older than the configured interval.
    The interval gate reads the artifact's own `collected_at`, so it survives a
    collector restart (unlike a monotonic in-memory timer)."""
    if not getattr(settings, "dhcp_intel_enabled", False):
        return
    targets = load_targets()
    if not targets:
        return
    existing = load()
    if existing is not None:
        age = _age_sec(existing.get("collected_at"))
        if age is not None and age < settings.dhcp_intel_interval:
            return  # collected recently enough
    intel = collect_all(
        targets,
        winrm_timeout=settings.dhcp_intel_winrm_timeout,
        time_budget=settings.dhcp_intel_time_budget,
    )
    _store(intel)


# ---------------------------------------------------------------------------
# Artifact + target-file IO
# ---------------------------------------------------------------------------


def load() -> dict[str, Any] | None:
    """Read the last-written intel artifact (for the bundle + the interval gate)."""
    try:
        return json.loads(INTEL_FILE.read_text())
    except FileNotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001 — a corrupt file shouldn't wedge bundling
        log.warning("could not read dhcp intel artifact", error=str(exc))
        return None


def load_targets() -> list[dict[str, Any]]:
    """Read the 0600 target list check-in wrote from the dashboard push."""
    try:
        data = json.loads(TARGETS_FILE.read_text())
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("could not read dhcp targets", error=str(exc))
        return []


def _store(intel: dict[str, Any]) -> None:
    """Write the intel artifact (0644 — it holds only server config the operator
    owns, no credentials — so the bundle builder can read it like the other
    box-global artifacts)."""
    try:
        INTEL_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = INTEL_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(intel))
        os.replace(str(tmp), str(INTEL_FILE))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not write dhcp intel artifact", error=str(exc))


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _age_sec(iso: Any) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(str(iso))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return (datetime.now(UTC) - dt).total_seconds()
    except Exception:  # noqa: BLE001
        return None


def _scrub(text: str, secret: str) -> str:
    """Never let a credential leak into a stored/logged error string."""
    if secret and secret in text:
        text = text.replace(secret, "***")
    return text


def _short(text: str, limit: int = 300) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit] + "…"


# ---------------------------------------------------------------------------
# Transport auto-detection + Kerberos (DHCP-8)
# ---------------------------------------------------------------------------
# Hardened AD environments DISABLE NTLM on WinRM (the 401 offers only Negotiate/
# Kerberos). So transport defaults to "auto": probe the endpoint's
# WWW-Authenticate and pick NTLM where it's offered, else Kerberos — the operator
# never has to know the difference. For Kerberos we kinit the same username +
# password into a private ccache and let pywinrm's gssapi transport use it; the
# realm + KDC come from DNS (nothing hardcoded). Kerberos needs the sensor clock
# within ~5 min of AD.

KRB5_CONF_PATH = "/var/lib/netmon/krb5.conf"


def _detect_transport(endpoint: str, timeout: int) -> str | None:
    """Choose a transport from the WinRM 401 challenge: 'ntlm' if the server offers
    bare NTLM, 'kerberos' if it offers Negotiate/Kerberos, None if undetermined
    (caller falls back to ntlm). Best-effort — never raises."""
    try:
        import requests
        import urllib3

        urllib3.disable_warnings()  # self-signed WinRM https is expected
        resp = requests.post(
            endpoint,
            data=b"0",  # a body avoids the 411 some listeners return on empty POST
            headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
            timeout=timeout,
            verify=False,
        )
        auth = resp.headers.get("www-authenticate", "").lower()
    except Exception:  # noqa: BLE001 — probe is advisory only
        return None
    if "ntlm" in auth:
        return "ntlm"
    if "kerberos" in auth or "negotiate" in auth:
        return "kerberos"
    return None


def _realm_from_server(ip: str) -> str | None:
    """Kerberos realm from the server's DNS domain via reverse lookup, e.g.
    10.0.0.10 -> dc01.sbcss.org -> SBCSS.ORG."""
    import socket

    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:  # noqa: BLE001
        return None
    parts = host.split(".", 1)
    return parts[1].upper() if len(parts) == 2 and parts[1] else None


def _write_krb5_conf(realm: str) -> None:
    """Minimal krb5.conf: the realm + DNS-based KDC discovery (no hardcoded KDCs)."""
    conf = (
        "[libdefaults]\n"
        f"    default_realm = {realm}\n"
        "    dns_lookup_kdc = true\n"
        "    dns_lookup_realm = true\n"
        "    rdns = false\n"
    )
    path = Path(KRB5_CONF_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(conf)


def _kinit(user: str, password: str, server_ip: str) -> str:
    """Acquire a Kerberos ticket for `user` into a private ccache and return its
    path (exported via KRB5CCNAME for pywinrm's gssapi transport). The realm comes
    from the UPN (user@domain) or, for a down-level DOMAIN\\user, the server's DNS
    domain. Raises with a clean message on failure."""
    import os
    import subprocess
    import tempfile

    if "@" in user:
        principal = user
        realm = user.rsplit("@", 1)[1].upper()
    elif "\\" in user:
        dom, uname = user.split("\\", 1)
        realm = _realm_from_server(server_ip) or dom.upper()
        principal = f"{uname}@{realm}"
    else:
        realm = _realm_from_server(server_ip) or ""
        principal = f"{user}@{realm}" if realm else user
    if not realm:
        raise RuntimeError("could not determine the Kerberos realm — use the user@DOMAIN form")

    _write_krb5_conf(realm)
    fd, ccache = tempfile.mkstemp(prefix="netmon_dhcp_krb5cc_")
    os.close(fd)
    env = {**os.environ, "KRB5_CONFIG": KRB5_CONF_PATH, "KRB5CCNAME": ccache}
    proc = subprocess.run(
        ["kinit", principal],
        input=(password + "\n").encode(),
        env=env,
        capture_output=True,
        timeout=20,
    )
    if proc.returncode != 0:
        _cleanup_ccache(ccache)
        msg = (proc.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(msg or f"kinit failed (rc={proc.returncode})")
    # pywinrm's gssapi transport reads the ambient ccache + config.
    os.environ["KRB5_CONFIG"] = KRB5_CONF_PATH
    os.environ["KRB5CCNAME"] = ccache
    return ccache


def _cleanup_ccache(ccache: str) -> None:
    import contextlib
    import os

    with contextlib.suppress(Exception):
        os.remove(ccache)
