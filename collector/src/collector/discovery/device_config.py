"""Network DEVICE config backup (NCM-1).

Fetch running + startup configuration from a district's managed network devices
(switches / routers / firewalls) over READ-ONLY SSH, redact secrets ON THE BOX
before anything leaves it, and ship the redacted configs box-global in the hourly
bundle as `device_configs.json`.

Scope: the configs of the NETWORK GEAR the sensor monitors — NOT this box's own
/etc/netmon files. (The sensor-self config backup was retired: netmon.env +
snmp.yaml are a materialization of the dashboard's desired_config, so a dead box
is redeployed rather than restored.)

Security / robustness posture (mirrors dhcp_server.py):
  * OFF by default; targets + per-device SSH credentials ride a 0600 JSON file
    written by check-in from the dashboard push (never argv, never env).
  * Every target isolated in try/except — an unreachable device or bad credential
    records a status/error and never crashes the poll loop.
  * Bounded by a per-device SSH timeout AND a whole-pass wall-clock budget.
  * netmiko is imported lazily so a box without the dep (feature off) imports clean.
  * READ-ONLY: only `show`-class commands are ever sent and config mode is NEVER
    entered — the contract is a show-only account (IOS parser view / NX-OS
    network-operator / AOS-CX operators / ICX `privilege 5`). See the SEC threat
    model. Enable mode is NEVER entered EXCEPT on Ruckus ICX, where `show
    running-config` exists only in privileged EXEC; there it is entered once, with
    the same credential, and a read-only account stays read-only. See
    _icx_connection_class.
  * REDACTION: secrets (snmp communities, local password hashes, enable secret,
    radius/tacacs keys, PSKs, private-key blocks) are masked with a deterministic
    keyed token BEFORE the config is written, so the plaintext secret never leaves
    the LAN. See _redact_config.

Output (ARTIFACT_FILE, 0644, shipped as `device_configs.json`; contains NO plaintext
secrets, only redacted device config the operator owns):

    {
      "collected_at": "<iso8601 utc>",
      "devices": [
        {"target_id", "host", "label", "platform", "status": "ok",
         "running_config": "<redacted text>", "startup_config": "<redacted text|null>",
         "fetched_at": "<iso>"},
        {"target_id", "host", "status": "error", "error": "..."},
        ...
      ],
      "stats": {"targets", "ok", "errors", "elapsed_sec", "budget_exhausted"}
    }
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from . import device_ssh_diag as ssh_diag

log = structlog.get_logger(__name__)

# Target list (0600, secrets) written by checkin from the dashboard push, and the
# box-global redacted artifact the bundle ships. Live under the same state dir as
# the other pushed-config files (dhcp-targets, wifi-profiles).
TARGETS_FILE = Path("/var/lib/netmon/device-config-targets.json")
ARTIFACT_FILE = Path("/var/lib/netmon/device_configs.json")
# Per-box HMAC key for redaction tokens (0600). See _redact_key.
_REDACT_KEY_FILE = Path("/var/lib/netmon/device-config-redact.key")

# Per-config cap — a healthy switch config is well under this; a runaway output
# gets rejected rather than eating memory / bloating the bundle.
_MAX_CONFIG_BYTES = 4 * 1024 * 1024

# Per-platform fetch commands (netmiko device_type -> running / startup show cmds).
# netmiko disables paging automatically in session_preparation, and we NEVER enter
# config mode (enable only on ICX — see _icx_connection_class). Juniper/EXOS have no
# separate startup (single committed/running config), so startup is None there.
# ICX (FastIron) is Cisco-like, but `show configuration` is its STARTUP config.
_PLATFORM_CMDS: dict[str, dict[str, str | None]] = {
    "cisco_ios": {"running": "show running-config", "startup": "show startup-config"},
    "cisco_xe": {"running": "show running-config", "startup": "show startup-config"},
    "cisco_nxos": {"running": "show running-config", "startup": "show startup-config"},
    "aruba_aoscx": {"running": "show running-config", "startup": "show startup-config"},
    "aruba_osswitch": {"running": "show running-config", "startup": "show config"},
    "juniper_junos": {"running": "show configuration", "startup": None},
    "ubiquiti_edgeswitch": {"running": "show running-config", "startup": "show startup-config"},
    "netgear_prosafe": {"running": "show running-config", "startup": "show startup-config"},
    "extreme_exos": {"running": "show configuration", "startup": None},
    "ruckus_fastiron": {"running": "show running-config", "startup": "show configuration"},
}


# ---------------------------------------------------------------------------
# Redaction — mask secrets ON THE BOX before the config is written / bundled.
# ---------------------------------------------------------------------------
# Well-known-bad values we reveal (as a labeled token) so the AI can flag them
# specifically — e.g. a default SNMP community "public"/"private" or "ro"/"rw".
_KNOWN_BAD = {"public", "private", "cisco", "admin", "password", "secret", "ro", "rw"}


def _token(secret: str, key: bytes) -> str:
    """Deterministic keyed token for a secret. Same secret -> same token (so a
    rotation shows as drift, an unchanged secret doesn't), not reversible without the
    box-resident key. ACCEPTED RISK: identical secrets across sites yield identical
    tokens, so credential reuse between districts is visible in the cloud — a
    deliberate trade for diff-stability."""
    norm = secret.strip().strip('"').strip("'")
    low = norm.lower()
    if low in _KNOWN_BAD:
        return f"<REDACTED:DEFAULT-{low}>"
    digest = hmac.new(key, norm.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:10]
    return f"<REDACTED:{digest}>"


# Multi-line key blocks — keep the fences, drop the body. Generic PRIVATE KEY label
# so OpenSSH / DSA / EC / PKCS#8 (ENCRYPTED) all match, plus OpenVPN static keys.
_BLOCK_RES = [
    re.compile(r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----).*?(-----END [A-Z0-9 ]*PRIVATE KEY-----)", re.S),
    re.compile(r"(-----BEGIN OpenVPN Static key V1-----).*?(-----END OpenVPN Static key V1-----)", re.S),
]
# A BEGIN…PRIVATE KEY fence NOT immediately followed by our token = a truncated /
# unhandled key whose body survived → fail closed (don't ship that config).
_LEAKED_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?!\s*<REDACTED:key-block>)")

# Line-oriented secret patterns. Each captures the secret as (?P<sec>...). ALL are
# evaluated against the SAME text and their spans unioned into ONE replace pass, so
# no pattern mutates text another relies on (the order-dependence leak class).
# re.M | re.I. Hardened per the Fable adversarial review 2026-07-16.
_REDACT_PATTERNS = [
    re.compile(p, re.M | re.I)
    for p in (
        # -- Cisco IOS / IOS-XE / NX-OS --
        r"^(\s*snmp-server community )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*snmp-server host \S+ (?:vrf \S+ )?(?:informs |traps )?(?:version (?:v?1|v?2c|v?3 (?:auth|noauth|priv)) )?(?:community )?)(?P<sec>\S+)",
        r"(\bsnmp-server user \S+ \S+ .*?\bauth (?:md5|sha(?:-?(?:224|256|384|512))?) )(?P<sec>\S+)",
        r"(\bsnmp-server user \S+ .*?\bpriv (?:aes[ -]?(?:128|192|256)? |des(?:56)? |3des )?)(?P<sec>(?!localizedkey\b|access\b)\S+)",
        r"^(\s*key config-key password-encrypt )(?P<sec>.+?)\s*$",
        r"^(\s*crypto isakmp key (?:[06] )?)(?P<sec>.+?)(?=\s+(?:address|hostname)\b|\s*$)",
        r"^(\s*(?:ikev[12] (?:local-authentication |remote-authentication )?)?pre-shared-key (?:address \S+ |hostname \S+ )?(?:local |remote )?(?:key |hex )?(?:[06] )?)(?P<sec>.+?)\s*$",
        r"^(\s*(?:tacacs|radius)-server (?:host \S+.*? )?key (?:encrypted )?(?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*server-private \S+ .*?\bkey (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*client \S+ (?:vrf \S+ )?server-key (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*(?:standby|vrrp|glbp) \d+ authentication (?:md5 key-string (?:[0-7] )?|text ))(?P<sec>.+?)\s*$",
        r"^(\s*security wpa psk set-key (?:ascii|hex) (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*wpa-psk (?:ascii|hex) (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*ppp (?:chap password|pap sent-username \S+ password) (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*ip (?:ftp|http client) password (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*ip nhrp authentication )(?P<sec>\S+)",
        r"^(\s*(?:ip |ipv6 )?ospf (?:message-digest-key \d+ md5|authentication-key) (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*ntp authentication-key \d+ (?:md5|sha1|sha2|cmac-aes-128|hmac-sha\S*) )(?P<sec>\S+)",
        r"^(\s*enable (?:secret|password) (?:level \d+ )?(?:encrypted )?(?:[0-9] )?)(?P<sec>.+?)\s*$",
        r"^(\s*username \S+ .*?(?:password|secret) (?:[0-9] )?)(?P<sec>.+?)\s*$",
        r"^(\s*neighbor \S+ password (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*key-string (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*key (?:encrypted )?(?:[0-7] )?)(?P<sec>(?!chain\b|config-key\b|encrypted\b)(?!\d+\s*$).+?)\s*$",
        r"^(\s*pac key (?:[0-7] )?)(?P<sec>.+?)\s*$",
        r"^(\s*(?:isis password|area-password|domain-password) )(?P<sec>\S+)",
        r"^(\s*sap pmk )(?P<sec>\S+)",
        # -- Cisco ASA --
        r"^(\s*passwd )(?P<sec>\S+)",
        r"^(\s*ldap-login-password )(?P<sec>.+?)\s*$",
        r"^(\s*failover key (?:hex )?)(?P<sec>\S+)",
        r"^(\s*snmp-server host \S+ \S+ (?:trap |poll )?community )(?P<sec>\S+)",
        # -- Aruba AOS-CX: 'ciphertext'/'plaintext' is ALWAYS immediately followed by
        #    the secret (user/radius/tacacs/snmpv3/ntp/keychain). Unanchored so it
        #    fires on BOTH secrets of an snmpv3 double-secret line. --
        r"(\b(?:ciphertext|plaintext) )(?P<sec>\S+)",
        # -- Aruba AOS-S / ProCurve (quoted or bare) --
        r"^(\s*password (?:manager|operator|all) .*?(?:sha1|sha256|plaintext) )(?P<sec>\"[^\"]*\"|\S+)",
        r"(\bencrypted-key )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*key-chain \S+ key \d+ key-string )(?P<sec>\"[^\"]*\"|.+?)\s*$",
        r"(\bkey-value )(?P<sec>\"[^\"]*\"|\S+)",
        # -- Ubiquiti EdgeOS (brace + set forms) --
        r"(\b(?:encrypted|plaintext)-password )(?P<sec>\"[^\"]*\"|\S+)",
        r"(\bpre-shared-secret )(?P<sec>\"[^\"]*\"|\S+)",
        r"(\bprivate-key )(?P<sec>\"[^\"]*\"|\S+)",
        # -- Ubiquiti EdgeSwitch / Netgear ProSafe (FASTPATH) --
        r"^(\s*radius server key (?:auth|acct) \S+ (?:encrypted )?)(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*snmp-server community (?:r[ow] )?)(?P<sec>\"[^\"]*\"|\S+)",
        # FASTPATH's OTHER community forms put a SUBCOMMAND KEYWORD where Cisco puts
        # the secret — `community ipaddr <ip> <name>` / `ipmask <mask> <name>` /
        # `mode <name>` — so the community sits at the END of the line. Without these
        # three the Cisco-shaped pattern above masks the KEYWORD and the real
        # community shipped in cleartext. (NCM-4; the keyword also still gets a token
        # of its own, exactly as `r[ow]` does — see the note in _redact_config.)
        r"^(\s*snmp-server community (?:(?:ipaddr|ipmask) \S+|mode) )(?P<sec>\"[^\"]*\"|\S+)",
        r"(\b(?:auth|priv)-(?:md5|sha\d*|des|aes\d*) (?:key )?)(?P<sec>\"[^\"]*\"|\S+)",
        # -- Extreme EXOS --
        r"^(\s*(?:create|configure) account .*?\bencrypted )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*configure snmp add community (?:readonly|readwrite) (?:encrypted )?)(?P<sec>\"[^\"]*\"|\S+)",
        # EXOS SNMPv3 users: `configure snmpv3 add user <u> authentication <md5|sha>
        # <pass> privacy <des|aes> <pass>`. Spelled out, not the hyphenated `auth-md5`
        # FASTPATH form above — and `_SECRET_KEYWORD_RE` knows neither `authentication `
        # nor `privacy `, so the backstop never saw these either and BOTH passwords
        # shipped in cleartext. Found while fixing the FASTPATH community leak; same
        # class, independent gap.
        #
        # ⚠️ ANCHORED TO THE EXOS COMMAND ON PURPOSE. `authentication ` and `privacy `
        # are ordinary English AND ordinary Cisco/Aruba syntax; unanchored, every
        # discriminator here is optional so `privacy ` degenerated to `privacy \S+` and
        # masked the next word of any banner reading "...district privacy policy...",
        # while `authentication (md5|sha) ` swallowed the literal keyword in Cisco's
        # `standby N authentication md5 key-chain <name>`. Both silently corrupt config
        # on cisco_ios/aruba_aoscx — the only two platforms in production. EXOS is the
        # one platform that spells these out, so anchoring costs nothing and removes
        # the whole class of cross-vendor collateral.
        # The optional discriminators cover EXOS's display forms too: `show config`
        # renders a stored key as `auth-encrypted localized-key <hex>` /
        # `privacy-encrypted localized-key <hex>`. Without them the pattern masks the
        # DISCRIMINATOR and the key itself ships in cleartext — the FASTPATH failure
        # shape, reproduced inside the fix for it. ⚠️ These EXOS forms are written to
        # the documented grammar and have NOT been checked against a real device
        # capture (no EXOS device is enrolled yet); confirm against `show configuration`
        # from real gear before trusting them.
        r"^(\s*configure snmpv3 add user .*?\bauthentication (?:md5|sha\d*) (?:auth-encrypted |encrypted )?(?:localized-key |hex )?)(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*configure snmpv3 add user .*?\bprivacy (?:(?:3?des|aes\d*) )?(?:privacy-encrypted |encrypted )?(?:localized-key |hex )?)(?P<sec>\"[^\"]*\"|\S+)",
        r"(\bshared-secret (?:encrypted )?)(?P<sec>\"[^\"]*\"|\S+)",
        r"(\bsimple-password )(?P<sec>\"[^\"]*\"|[^\s;]+)",
        # -- Juniper Junos (set-form) --
        r"^(\s*set .*\bencrypted-password )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*set .*\bsecret )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*set snmp community )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*set .*\b(?:authentication-key|privacy-key|authentication-password|privacy-password) )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*set .*\bpre-shared-key (?:ascii-text|hexadecimal) )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*set .*\bkey (?:ascii-text|hexadecimal) )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*set .*\bsimple-password )(?P<sec>\"[^\"]*\"|\S+)",
        # -- Juniper Junos (brace-form; secret excludes the trailing ';') --
        r"^(\s*encrypted-password )(?P<sec>\"[^\"]*\"|[^\s;]+)",
        r"^(\s*secret )(?P<sec>\"[^\"]*\"|[^\s;]+)",
        r"^(\s*community )(?P<sec>(?!r[ow]\b|read\b|write\b|encrypted\b|ciphertext\b|plaintext\b)(?:\"[^\"]*\"|[^\s;{]+))(?=\s*[;{]|\s*$)",
        r"^(\s*(?:authentication-key|privacy-key|authentication-password|privacy-password|chap-secret) )(?P<sec>(?!\d+ type\b|key-id\b)(?:\"[^\"]*\"|[^\s;]+))",
        # -- Cross-vendor backstops --
        r"(\b(?:ftp|sftp|scp|tftp|https?)://[^:/@\s]+:)(?P<sec>[^@\s]+)(?=@)",
        r"(\b(?:passphrase|wpa-passphrase|presharedkey|psk|auth-password|priv-password|wep-key\d?) )(?P<sec>\"[^\"]*\"|\S+)",
    )
]
# Ruckus / Brocade ICX (FastIron) — applied ON TOP OF the list above, and ONLY when
# the target's platform is `ruckus_fastiron`. Scoped on purpose: the `<digit> $blob`
# catch-all below would also mask free text on other vendors ("Room 2 $5" in a
# description or banner), and any change to their redacted output re-versions every
# existing device's backup with a phantom config change.
#
# FastIron prints most secrets as `<type-digit> <value>`: `8 $1$salt$hash` (md5-crypt,
# which _DOLLAR_RE already claims) or `2 $<base64>` — a REVERSIBLE encoding with public
# decoders and NO second `$`, so _DOLLAR_RE does not see it. The Cisco-shaped patterns
# above mask the type DIGIT as if it were the secret (`snmp-server community 2 $x ro`
# -> the `2`) and leave the real value to the backstop — the FASTPATH failure shape.
# The plaintext forms (`no service password-encryption`) matter as much: a short
# password is not credential-shaped enough for the backstop to catch.
_ICX_REDACT_PATTERNS = [
    re.compile(p, re.M | re.I)
    for p in (
        r"^(\s*enable (?:super-user|read-only|port-config)-password (?:[0-9] )?)(?P<sec>.+?)\s*$",
        r"^(\s*enable telnet password )(?P<sec>.+?)\s*$",
        r"^(\s*snmp-server community [0-9] )(?P<sec>\"[^\"]*\"|\S+)",
        r"^(\s*snmp-server host \S+ version v(?:1|2c) (?:[0-9] )?)(?P<sec>\"[^\"]*\"|\S+)",
        r"(\bsnmp-server user .*?\bpriv encrypted (?:des|aes\S*) )(?P<sec>\S+)",
        r"(\bmd5-authentication key-id \d+ key (?:[0-9] )?)(?P<sec>\S+)",
        # Current OSPFv2/v3 + virtual-link form:
        # `[ipv6 ospf|area N virtual-link IP] authentication md5|hmac-sha-1|hmac-sha-256
        # key-id N key <k>`.
        r"^(\s*(?:ip ospf |ipv6 ospf |area \S+ virtual-link \S+ )authentication (?:md5|hmac-sha-1|hmac-sha-256) key-id \d+ key (?:[0-9] )?)(?P<sec>\S+)",
        # key-chain body (`key-id N` / `  password <k>`): INDENTED only, so a banner
        # line that merely starts with the word "password" is left alone.
        r"^([ \t]+password (?:[0-9] )?)(?P<sec>\S+)",
        # OSPF interface / virtual-link plain-text auth (08.0.70+).
        r"^(\s*(?:ip ospf |area \S+ virtual-link \S+ )authentication plain-text (?:[0-9] )?)(?P<sec>\S+)",
        # VRRP / VRRP-E `auth-type simple-text-auth|md5-auth <pw>` and VSRP-aware
        # `vsrp-aware vrid N simple-text-auth <pw>`.
        r"(\b(?:simple-text-auth|md5-auth) (?:[0-9] )?)(?P<sec>\S+)",
        r"^(\s*authentication-key key-id \d+ (?:md5|sha1|sha256) (?:[0-9] )?)(?P<sec>\S+)",
        r"^(\s*mac-authentication password-override (?:[0-9] )?)(?P<sec>\S+)",
        r"(\bauth-mode passcode static )(?P<sec>\S+)",
        r"^(\s*radius-client coa host \S+ .*?\bkey (?:[0-9] )?)(?P<sec>\S+)",
        # Any `<type-digit> $<blob>` pair, on any ICX command: the encoded form is
        # always written this way, so a command this list has never heard of still
        # masks.
        r"((?:^|\s)[0-9] )(?P<sec>\$[^\s\"';]+)",
    )
]

# G1: any $-format hash / reversible blob anywhere on any line — the highest-value
# catch-all (Cisco type-5/8/9, Junos $9$, Linux $5$/$6$, apr1, bcrypt). Whole match
# IS the secret.
_DOLLAR_RE = re.compile(r"(?P<sec>\$(?:9|1|2[aby]?|5|6|8|y|sha1|apr1)\$[^\s\"';]+)")

# Fail-closed backstop: a secret-family keyword followed by a credential-shaped tail
# that NO pattern masked gets that tail masked + counted — so a silent pattern gap
# becomes a visible signal instead of a leak.
# ⚠️ THIS GATE IS ITSELF A PATTERN, AND A GAP HERE DISARMS THE BACKSTOP ENTIRELY —
# the same failure mode as the "line already looks handled" guard, one level up. Both
# EXOS SNMPv3 leaks were invisible for exactly this reason: the list carried
# `authentication-key` and `auth-key` but not bare `authentication`, and `\bpriv\b`
# does NOT match "privacy". Prefer a false keyword hit (the tail still has to look
# credential-shaped) over a missing one.
_SECRET_KEYWORD_RE = re.compile(
    r"(?i)\b(?:passwd|password|secret|passphrase|community|pre-shared|shared-secret|"
    r"auth-key|authentication-key|authentication|priv|privacy|psk|wep|cak|key-string)\b"
)
_SECRET_TAIL_RE = re.compile(r"\"[^\"]{6,}\"|\$\S+|[A-Za-z0-9+/=]{12,}|\S*\d\S{7,}")
# Tokens this module has already inserted. The backstop blanks these out and scans
# what is LEFT, instead of skipping any line that carries one — see _backstop_line.
_TOKEN_RE = re.compile(r"<REDACTED:[^>\s]*>")
# A bare dotted quad (optionally /len) — an ACL address or a netmask, never a
# credential. See _next_credential_tail for why the backstop steps over one.
_IPV4_LITERAL_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?")
# Letters in ONE case, no digits — a grammar keyword (Junos `authorization`), not the
# base64/hex blob _SECRET_TAIL_RE's {12,} alternative is hunting. See below.
_PLAIN_WORD_RE = re.compile(r"[a-z]+|[A-Z]+")
# Fixed 802.1X / AAA grammar words that sit right after the bare `authentication`
# keyword and are long enough to trip the {12,} blob alternative. Unlike the
# single-case guard these are exact vendor keywords, so they are stepped over
# ANYWHERE on the line, token or not. Every `<REDACTED:suspect>` in the stored
# production snapshots (2026-10-23: 340 lines, 22 snapshots, two platforms) was one
# of the first two, i.e. 100% false positives that also corrupted the stored config:
#   cisco_ios    `authentication timer reauthenticate server`
#   aruba_aoscx  `aaa authentication port-access dot1x authenticator`
# The other two are the same IOS command family (`authentication event server alive
# action reinitialize`, `authentication port-control force-unauthorized`).
# Exact, lowercase, whole-candidate matches only: a credential-shaped tail that is
# not literally one of these words is still masked and counted.
_AUTH_GRAMMAR_WORDS = frozenset({"reauthenticate", "authenticator", "reinitialize", "unauthorized"})


def _next_credential_tail(scan: str, start: int, run_on_from: int) -> re.Match[str] | None:
    """First credential-shaped tail at/after `start`, skipping known non-credentials.

    Two candidates are stepped over — SKIPPED AND CONTINUED past, never abandoning
    the line, so a real secret sitting further right is still caught:

    * **A bare IPv4 literal, but only at/after `run_on_from`** (see below for that
      offset). A dotted quad trips `_SECRET_TAIL_RE`'s "random-ish string containing a
      digit" alternative, but on FASTPATH's `snmp-server community ipaddr <ip> <name>`
      it is CONFIG — the ACL address saying who may poll SNMP. Masking it hides config
      the operator owns (an over-broad SNMP ACL is itself a finding) and would fire
      `redaction_suspects` on every healthy FASTPATH box, turning a review signal into
      background noise. ⚠️ The offset guard matters: on an UNTOKENED line the backstop
      is the only guard there is, and skipping dotted quads there silently un-caught
      `configure snmpv3 add community <ip> user ...` — a community literally set to an
      IP address, which is a real lazy-admin habit and which the pre-fix code DID
      catch. FASTPATH ipaddr/ipmask lines always carry a token by the time the
      backstop runs, so their ACL address is still kept.

    * **A single-case alphabetic word, but only at/after `run_on_from`** — the offset
      of the first token already on the line. Before that offset nothing has been
      masked, so the original full-strength heuristic applies unchanged. At/after it
      we are scanning the REMAINDER of a partly-handled line, where the run of text
      is far more likely to be a grammar keyword the pattern left behind than a
      secret: `set snmp community <TOK> authorization read-only` otherwise masks
      Junos's `authorization` on every device that has an SNMP community.

    * **One of `_AUTH_GRAMMAR_WORDS`, at any offset** — vendor keywords, not a
      heuristic, so no offset guard is needed.

    The trade in all cases — a secret that is literally a dotted quad, literally
    12+ same-case letters with no digit sitting after another masked value, or
    literally one of four 802.1X keywords — is deliberate and narrow. The ~60 named
    patterns still claim such a value on every grammar we support; this is the
    catch-all behind them, not the only guard.
    """
    at = start
    while True:
        tm = _SECRET_TAIL_RE.search(scan, at)
        if tm is None:
            return None
        cand = tm.group(0)
        if cand in _AUTH_GRAMMAR_WORDS or (tm.start() >= run_on_from and (
            _IPV4_LITERAL_RE.fullmatch(cand) or _PLAIN_WORD_RE.fullmatch(cand)
        )):
            at = tm.end()  # run-on argument text, not the grammar's secret slot
        else:
            return tm


def _backstop_line(line: str) -> tuple[str, int]:
    """Fail-closed sweep of ONE line: mask credential-shaped tails no pattern claimed.

    ⚠️ This scans the UN-REDACTED REMAINDER of the line. It deliberately does NOT
    skip lines that already carry a token, because a PARTIALLY-handled line is
    exactly where a pattern gap hides — "this line looks handled" is the wrong shape
    for a fail-closed check.

    That is not hypothetical: it is how three FASTPATH SNMP communities shipped in
    cleartext. `snmp-server community ipaddr <ip> <secret>` matched the Cisco-shaped
    pattern, which masked the SUBCOMMAND KEYWORD as if it were the secret; the token
    that produced then switched this backstop off for the very line whose real
    community was still in the clear, and `suspects` stayed 0. The one mechanism
    built to catch a pattern gap was disarmed by the partial match that created it.

    Existing tokens are blanked to spaces of the SAME LENGTH, so offsets found in
    `scan` index straight back into `line`, and a space matches none of the
    credential-shape alternatives (so a token can never be re-masked as its own
    suspect). Spans are replaced right-to-left, mirroring _redact_config's one-pass
    architecture. Returns (line, masks_applied).
    """
    scan = _TOKEN_RE.sub(lambda m: " " * (m.end() - m.start()), line)
    first_token = _TOKEN_RE.search(line)
    run_on_from = first_token.start() if first_token else len(line)
    spans: list[tuple[int, int]] = []
    pos = 0
    while True:
        km = _SECRET_KEYWORD_RE.search(scan, pos)
        if km is None:
            break
        tm = _next_credential_tail(scan, km.end(), run_on_from)
        if tm is None:
            break
        spans.append((tm.start(), tm.end()))
        pos = tm.end()  # strictly increases -> terminates
    for s, e in reversed(spans):
        line = line[:s] + "<REDACTED:suspect>" + line[e:]
    return line, len(spans)


def _redact_config(
    text: str | None, key: bytes, platform: str | None = None
) -> tuple[str | None, int]:
    """Mask every recognized secret. Returns (redacted_text, suspect_count).

    `platform` adds that platform's own patterns on top of the cross-vendor list
    (today only `ruckus_fastiron`, see _ICX_REDACT_PATTERNS). Omitting it is the
    pre-ICX behaviour, byte for byte.

    Architecture (per the Fable adversarial review): collect the (?P<sec>) spans of
    ALL patterns against the SAME text, union overlaps, and replace in ONE right-to
    -left pass — so no pattern mutates text another relies on. Over-masking is safe;
    leaking is not.

    ⚠️ On FASTPATH (`ubiquiti_edgeswitch` / `netgear_prosafe`) the access mode and
    the subcommand keyword sit WHERE CISCO PUTS THE SECRET, so the Cisco-shaped
    pattern masks them too and a line yields TWO tokens:

        snmp-server community rw <secret>      -> community <REDACTED:DEFAULT-rw> <REDACTED:hash>
        snmp-server community mode <secret>    -> community <REDACTED:hash> <REDACTED:hash>

    That extra token is deliberately KEPT, not cleaned up. `<REDACTED:DEFAULT-rw>` /
    `-ro` is the only thing that reveals FASTPATH access mode at all, the dashboard
    reads exactly that shape (`src/lib/rules/config-parse.ts`, platform-scoped, so it
    is not mistaken for a weak community), and every historical snapshot carries it
    forever. Narrowing it here would need a fleet rollout and would silently
    invalidate that cloud-side parse. Interpretation belongs where interpretation
    happens; this function's job is only that no secret leaves the LAN."""
    if not text:
        return text, 0

    # 1. Multi-line key blocks: keep fences, drop body.
    for rx in _BLOCK_RES:
        text = rx.sub(r"\1\n<REDACTED:key-block>\n\2", text)

    # 2. Collect all secret spans over the (block-redacted) text.
    spans: list[list[int]] = []
    extra = _ICX_REDACT_PATTERNS if platform == "ruckus_fastiron" else []
    for rx in (*_REDACT_PATTERNS, *extra, _DOLLAR_RE):
        for m in rx.finditer(text):
            if m.groupdict().get("sec"):
                spans.append([m.start("sec"), m.end("sec")])

    # 3. Union overlapping spans, then replace right-to-left (token from the actual
    #    covered text, so an overlap masks the whole region).
    if spans:
        spans.sort()
        merged: list[list[int]] = []
        for s, e in spans:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        for s, e in reversed(merged):
            text = text[:s] + _token(text[s:e], key) + text[e:]

    # 4. Fail-closed backstop over the UN-REDACTED remainder of EVERY line (a
    #    partially-masked line is where a pattern gap hides — see _backstop_line).
    suspects = 0
    out: list[str] = []
    for line in text.split("\n"):
        line, n = _backstop_line(line)
        suspects += n
        out.append(line)
    return "\n".join(out), suspects


def _redact_key() -> bytes:
    """The per-box HMAC key for redaction tokens (0600), created once. Kept OFF the
    bundle + DB so a bundle/DB-only attacker can't brute-force low-entropy secrets
    back from the tokens. (A fully-compromised box already holds the SSH creds and
    can read the live configs directly, so the key protects the cloud plane, not
    that box's own districts — see the SEC threat model.)"""
    try:
        return _REDACT_KEY_FILE.read_bytes()
    except FileNotFoundError:
        key = os.urandom(32)
        try:
            _REDACT_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(_REDACT_KEY_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not persist redact key", error=str(exc))
        return key
    except Exception as exc:  # noqa: BLE001
        log.warning("could not read redact key; using ephemeral", error=str(exc))
        return os.urandom(32)


# ---------------------------------------------------------------------------
# Per-device fetch
# ---------------------------------------------------------------------------


class IcxEnableRejected(Exception):
    """ICX signed us in, then refused privileged (enable) mode for the credential."""


class IcxNoEnableAccess(Exception):
    """ICX signed us in, but offers no way into privileged mode for this account."""


# Credential prompts the device is waiting at, as the LAST line of its output.
_ICX_USER_PROMPT_RE = re.compile(r"(?:User Name|Login):\s*$", re.I)
_ICX_PASS_PROMPT_RE = re.compile(r"ssword:\s*$", re.I)
# How long to wait for the switch to settle after the one enable credential (a
# RADIUS/TACACS round trip can pause the reply for several seconds).
_ICX_ENABLE_SETTLE_SEC = 20.0
# "Quiet" = no new bytes for this long; polled every _ICX_POLL_SEC.
_ICX_QUIET_SEC = 1.0
_ICX_POLL_SEC = 0.1


# CSI / charset-select escapes a terminal may append to a prompt (`\x1b[K`, ...).
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]")


def _icx_last_line(text: str) -> str:
    text = _ANSI_RE.sub("", text)
    lines = [ln.strip() for ln in text.replace("\r", "\n").split("\n") if ln.strip()]
    return lines[-1] if lines else ""


def _icx_enable_verdict(after: str, base_prompt: str) -> str | None:
    """Classify switch output from its LAST line (used at every step of `enable`).

    "priv"   = the last line IS the privileged prompt `<base_prompt>#`.
    "unpriv" = the last line IS the unprivileged prompt `<base_prompt>>`.
    "user"   = the last line ends in a username prompt (`User Name:` / `Login:`).
    "pass"   = the last line ends in a password prompt (`Password:`).
    None     = not settled (banner / AAA text still arriving, or nothing yet).

    Only the final line is read, and only a WHOLE prompt line counts. Everything
    above it is banner, MOTD or AAA chatter whose words prove nothing — reviewers
    built false verdicts for every stream-matching variant: "Authorized login only",
    "Notice: SSH@sw" above a `Password:`, a hostname `SSH@login-switch#`, "Access
    denied for SSH@sw#", "Policy #17 denies ...".
    """
    last = _icx_last_line(after)
    if not last:
        return None
    # Normalise the prompt the same way as the reply: netmiko captured it raw, and a
    # prompt that arrived with an escape prefix (`\x1b[?25hSSH@sw>`) would otherwise
    # never equal the stripped reply.
    base_prompt = _ANSI_RE.sub("", base_prompt).strip()
    if base_prompt and last == base_prompt + "#":
        return "priv"
    if base_prompt and last == base_prompt + ">":
        return "unpriv"
    if _ICX_PASS_PROMPT_RE.search(last):
        return "pass"
    if _ICX_USER_PROMPT_RE.search(last):
        return "user"
    return None


def _icx_connection_class() -> Any:
    """netmiko's FastIron driver with ONE enable attempt instead of three.

    `show running-config` exists only in ICX privileged EXEC, so the stock driver's
    session_preparation always runs `enable`. Its enable() retries a rejected
    password up to three times per device, and the failure surfaces as a ValueError
    raised before ConnectHandler returns — which classify_exception cannot tell from
    any other pre-auth error, so the auth breaker never counts it. A district-wide
    enable mismatch would be three failed logins per switch, all night, uncounted:
    exactly the lockout the breaker exists to prevent.

    Here: one attempt, using the SSH credential itself (netmiko answers ICX's
    `User Name:` prompt with the username, then `secret`). That is the supported
    setup — `aaa authentication enable default local` (enable re-checks the same
    account) or `aaa authentication login privilege-mode` (the account lands in
    privileged mode and nothing is sent). A rejection raises IcxEnableRejected, which
    _fetch_one reports as stage `auth` so the breaker counts it.
    """
    from netmiko.ruckus import RuckusFastironSSH  # lazy, like ConnectHandler

    class _IcxReadOnlySSH(RuckusFastironSSH):  # type: ignore[misc]
        # True from the moment the switch asks for a credential until it shows the
        # privileged prompt. While True, nothing may be written: a refused enable
        # raises into netmiko's _try_session_preparation -> disconnect() -> the
        # Cisco cleanup(), which sends a RETURN (check_config_mode) and `exit` —
        # at a waiting `Password:` that is a second, empty login attempt.
        _icx_unresolved = False

        def cleanup(self, command: str = "exit") -> None:
            if self._icx_unresolved:
                return  # close the transport only (disconnect does that next)
            super().cleanup(command=command)

        def _icx_read_quiet(self, deadline: float) -> str:
            """Bytes that arrive until the channel has been quiet _ICX_QUIET_SEC.

            Returns "" when nothing arrives in that window. Deliberately NOT netmiko's
            read_channel_timing(): that one never returns empty — on a silent channel
            it waits out read_timeout and RAISES — so "the switch is waiting at its
            Password: prompt" would read as a timeout and every healthy ICX would be
            reported as a refused enable (Codex N12).
            """
            data = ""
            last_new = time.monotonic()
            while time.monotonic() < deadline:
                time.sleep(_ICX_POLL_SEC)
                new = str(self.read_channel() or "")
                if new:
                    data += new
                    last_new = time.monotonic()
                elif time.monotonic() - last_new >= _ICX_QUIET_SEC:
                    break
            return data

        def _icx_settle(self) -> tuple[str, str]:
            """Read without writing until the output settles on a whole prompt line.

            Returns (verdict, text). A credential prompt must STILL be the last line
            after a quiet window with nothing new (a banner can arrive in pieces and
            pause on "Login:"). "timeout" after _ICX_ENABLE_SETTLE_SEC or on any read
            error.
            """
            text = ""
            deadline = time.monotonic() + _ICX_ENABLE_SETTLE_SEC
            while time.monotonic() < deadline:
                try:
                    new = self._icx_read_quiet(deadline)
                except Exception:  # noqa: BLE001 — channel error
                    return "timeout", text
                text += new
                verdict = _icx_enable_verdict(text, str(getattr(self, "base_prompt", "")))
                if verdict in ("priv", "unpriv"):
                    return verdict, text
                if verdict in ("user", "pass") and not new.strip():
                    # Already the last line before this window, and the window
                    # brought nothing: the switch is waiting for it.
                    return verdict, text
            return "timeout", text

        def enable(
            self,
            cmd: str = "enable",
            pattern: str = "",
            enable_pattern: str | None = None,
            check_state: bool = True,
            re_flags: int = re.IGNORECASE,
        ) -> str:
            # Before `enable` we sit at the login prompt, so check_enable_mode()'s
            # RETURN is harmless here — and nowhere after.
            if check_state and self.check_enable_mode():
                return ""
            # Armed BEFORE `enable` is sent, cleared only at a whole prompt line:
            # any exception from here on must leave cleanup() unable to type into a
            # waiting credential prompt.
            self._icx_unresolved = True
            self.write_channel(self.normalize_cmd(cmd))
            sent_user = sent_secret = False
            while True:
                verdict, _text = self._icx_settle()
                if verdict == "priv":
                    # Includes "No password has been assigned yet..." followed by `#`:
                    # a switch with no super-user password grants privileged mode.
                    self._icx_unresolved = False
                    return ""
                if verdict == "unpriv":
                    self._icx_unresolved = False  # at `>`: nothing pending any more
                    if sent_user or sent_secret:
                        raise IcxEnableRejected("enable refused")
                    # Back at `>` without being asked for anything: no enable path
                    # for this account. No credential was offered, nothing can lock.
                    raise IcxNoEnableAccess("no enable path for this account")
                if verdict == "user" and not sent_user and not sent_secret:
                    sent_user = True
                    self.write_channel(self.normalize_cmd(self.username))
                    continue
                if verdict == "pass" and not sent_secret:
                    # The ONE credential. After it nothing more is written: a second
                    # prompt is a refusal, never answered.
                    sent_secret = True
                    self.write_channel(self.normalize_cmd(self.secret))
                    continue
                # A re-prompt, a timeout, or something we will not answer. Always
                # stage `auth` (the breaker counts it): erring that way can only stop
                # a run early, never lock an account.
                raise IcxEnableRejected(f"enable did not complete ({verdict})")

    return _IcxReadOnlySSH


def _connect(platform: str, **kwargs: Any) -> Any:
    """Open a netmiko session for `platform` (ICX gets its one-attempt driver).

    netmiko logs every channel write and read at DEBUG — on ICX that includes the
    enable password, on every platform the raw UNREDACTED config — and the
    collector's root logger runs at DEBUG whenever an operator sets
    NETMON_LOG_LEVEL=DEBUG, into a file `collect-logs` ships to the dashboard. Pin
    netmiko above DEBUG regardless.
    """
    logging.getLogger("netmiko").setLevel(max(logging.INFO, logging.getLogger("netmiko").level))
    if platform == "ruckus_fastiron":
        return _icx_connection_class()(device_type=platform, secret=kwargs.get("password", ""), **kwargs)
    from netmiko import ConnectHandler

    return ConnectHandler(device_type=platform, **kwargs)


# FastIron prints a header above the config — `Current configuration:` for running,
# `Startup-config data location is flash memory` / `Startup configuration:` and
# extra `!` separators for startup. They name the COMMAND, not the config, so left in
# they make every ICX read as permanently drifted (the ArubaOS-CX banner bug). The
# config proper always opens with its `ver <release>` line.
_ICX_VER_RE = re.compile(r"^ver\s+\S", re.M)


def _strip_icx_preamble(text: str | None) -> str | None:
    """Drop everything above the `ver` line (only if it is in the first 20 lines)."""
    if not text:
        return text
    m = _ICX_VER_RE.search(text)
    if m is None or text.count("\n", 0, m.start()) > 20:
        return text
    return text[m.start():]


def _fetch_one(
    target: dict[str, Any],
    *,
    key: bytes,
    ssh_timeout: int,
    discard_output: bool = False,
) -> dict[str, Any]:
    """Fetch one device's running (+ startup) config over SSH. Never raises.

    `discard_output=True` runs the IDENTICAL path — same platform profile, same
    commands, same timeouts — but throws the config away and reports only stage
    results. That is what "Test SSH" runs, and running the same code is the whole
    point: a passing test is a promise that tonight's backup will work. A test that
    exercised a lighter path would be a liar.

    Every failure is reported as a (stage, code) from device_ssh_diag, so the
    dashboard renders on-demand and nightly failures through one ladder with one
    vocabulary.
    """
    started = time.monotonic()
    host = str(target.get("host") or "").strip()
    platform = str(target.get("platform") or "").strip()
    base = {
        "target_id": target.get("target_id"),
        "host": host,
        "label": target.get("label"),
        "platform": platform,
    }

    def _fail(stage: str, code: str, **extra: Any) -> dict[str, Any]:
        elapsed = int((time.monotonic() - started) * 1000)
        return {
            **base,
            "status": "error",
            "stage": stage,
            "code": code,
            "error": code,  # legacy field; the CODE, never raw exception text
            "ladder": ssh_diag.stage_ladder(stage),
            "elapsed_ms": elapsed,
            **extra,
        }

    if not host:
        return _fail("reach", "error.no_host")
    cmds = _PLATFORM_CMDS.get(platform)
    if not cmds:
        return _fail("reach", "error.unsupported_platform")
    # Narrow before use: `startup` is legitimately None for platforms with no separate
    # startup config (Junos, EXOS), but `running` being absent would be a table bug.
    run_cmd = cmds.get("running")
    start_cmd = cmds.get("startup")
    if not run_cmd:
        return _fail("reach", "error.unsupported_platform")

    user = str(target.get("ssh_user") or "")
    password = str(target.get("ssh_password") or "")
    port = int(target.get("port") or 22)

    try:
        import netmiko  # noqa: F401 — lazy: only when a device is fetched
    except Exception as exc:  # pragma: no cover — dep-missing guard
        # The detail goes to the log, not the payload: this result renders in a
        # browser, and "only codes and numbers" has no useful exceptions.
        log.warning("netmiko unavailable", error=str(exc))
        return _fail("reach", "error.unclassified")

    conn = None
    running: str | None = None
    startup: str | None = None
    authenticated = False
    try:
        conn = _connect(
            platform,
            host=host,
            port=port,
            username=user,
            password=password,
            conn_timeout=ssh_timeout,
            auth_timeout=ssh_timeout,
            banner_timeout=ssh_timeout,
            fast_cli=False,
        )
        authenticated = True  # past this line, no failure can be a credential problem
        # str(): netmiko types send_command as str | list | dict (it can parse
        # structured output with a TextFSM template). We never pass one, so the
        # runtime value is always str — the cast is for the type checker.
        running = str(conn.send_command(run_cmd, read_timeout=ssh_timeout * 2))
        if start_cmd:
            try:
                startup = str(conn.send_command(start_cmd, read_timeout=ssh_timeout * 2))
            except Exception:  # noqa: BLE001 — startup is optional (may be unset)
                startup = None
    except IcxEnableRejected:
        # Signed in, then enable refused the same credential. Stage `auth` on purpose:
        # it IS a failed login attempt on the device, so the breaker must count it.
        log.info("device ssh failed", host=host, stage="auth", code="auth.enable_rejected")
        return _fail("auth", "auth.enable_rejected")
    except IcxNoEnableAccess:
        # Signed in; the switch has no enable path for this account. No password was
        # tried, nothing can lock — the account just needs privileged read access.
        log.info("device ssh failed", host=host, stage="authz", code="authz.no_read_access")
        return _fail("authz", "authz.no_read_access")
    except Exception as exc:  # noqa: BLE001 — connect / auth / timeout / read
        # Probe liveness ONLY for a pre-auth failure, and only to split the two
        # reach timeouts: "answers but SSH is filtered/off" vs "nothing there at
        # all" look identical to the SSH client and send the operator to different
        # buildings.
        ping_ok = None if authenticated else ssh_diag.tcp_ping(host, port)
        stage, code = ssh_diag.classify_exception(exc, ping_ok=ping_ok, authenticated=authenticated)
        log.info("device ssh failed", host=host, stage=stage, code=code)
        return _fail(stage, code, ping_ok=ping_ok)
    finally:
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:  # noqa: BLE001
                pass

    # Signed in, but the account isn't permitted to read the config. The password is
    # RIGHT — the least-privilege role was never applied to this box — and calling
    # this an auth failure sends the operator to rotate working credentials.
    if platform == "ruckus_fastiron":
        running = _strip_icx_preamble(running)
        startup = _strip_icx_preamble(startup)

    if ssh_diag.looks_like_authz_denial(running):
        return _fail("authz", "authz.no_read_access")

    if not running or not running.strip():
        return _fail("read", "read.empty")
    if len(running) > _MAX_CONFIG_BYTES:
        return _fail("read", "read.too_large")
    if startup and len(startup) > _MAX_CONFIG_BYTES:
        startup = None

    # Test mode: identical path, output discarded. Report stages + sizes only.
    if discard_output:
        return {
            **base,
            "status": "ok",
            "stage": None,
            "code": None,
            "ladder": ssh_diag.stage_ladder(None),
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "bytes_read": len(running),
            "has_startup": startup is not None,
        }

    red_run, sus_run = _redact_config(running, key, platform)
    red_start, sus_start = _redact_config(startup, key, platform)
    # Fail closed: if a private-key body survived redaction (e.g. a truncated PEM
    # whose END fence never arrived), do NOT ship the config — a leaked key is
    # unacceptable, so surface it as an error the operator sees instead.
    for red in (red_run, red_start):
        if red and _LEAKED_KEY_RE.search(red):
            return _fail("save", "save.redaction_failed")
    return {
        **base,
        "status": "ok",
        "running_config": red_run,
        "startup_config": red_start,
        # The total is kept for dashboards that predate the per-kind fields; it is
        # NOT a per-config count, and storing it on each snapshot read double.
        "redaction_suspects": sus_run + sus_start,
        "redaction_suspects_running": sus_run,
        "redaction_suspects_startup": sus_start,
        "fetched_at": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Whole-pass orchestration
# ---------------------------------------------------------------------------

#: Consecutive credential rejections that stop a run.
AUTH_BREAKER_THRESHOLD = 3


class _AuthBreaker:
    """Stops a pass once the same credential set is rejected N times in a row.

    A district-wide password typo must produce a handful of failed logins, not one
    per switch. ~110 rejections in a single pass is how a shared read-only account
    gets locked on every device at once — and how a district takes out its own
    RADIUS/TACACS server while merely trying to back up configs.

    Which outcomes count, and why:

    * ``auth`` — the only stage that counts. The device affirmatively rejected the
      credential, so the next device will almost certainly reject it too.
    * ``authz`` — deliberately does NOT count. The password *worked*; the account
      just isn't allowed to read the config. That's a role-provisioning gap, it
      locks nothing out, and stopping the run over it would hide every other
      device's real status behind a problem that isn't dangerous.
    * ``reach`` / ``ssh`` — neutral: they neither trip nor reset. An unreachable
      device says nothing about the credential either way. Resetting on one would
      let a few dead hosts sprinkled between live ones defeat the breaker entirely.
    * a success resets the counter — the credential demonstrably works here.

    Shared by all three consumers (nightly pass, "Back up now", "Test SSH") so the
    protection can't be present in one and missing in another.
    """

    __slots__ = ("consecutive", "threshold", "tripped")

    def __init__(self, threshold: int = AUTH_BREAKER_THRESHOLD) -> None:
        self.threshold = threshold
        self.consecutive = 0
        self.tripped = False

    def record(self, entry: dict[str, Any]) -> None:
        """Fold one device result into the counter."""
        if entry.get("stage") == "auth":
            self.consecutive += 1
            if self.consecutive >= self.threshold:
                self.tripped = True
        elif entry.get("status") == "ok":
            self.consecutive = 0

    def headroom(self) -> int:
        """How many more attempts may be in flight before the threshold is hit.

        Used to shrink the last wave of a concurrent run: with a fixed wave size the
        breaker can only be consulted *between* waves, so a wave of 4 launched at
        two-strikes would land 4 rejections against a documented limit of 3.
        """
        return max(1, self.threshold - self.consecutive)


def _skipped(target: dict[str, Any], code: str) -> dict[str, Any]:
    """A device the pass never attempted. Carries a taxonomy code, not free text —
    the dashboard renders `job.*` codes as muted 'didn't run' copy, and an
    unrecognised string would fall through to a generic 'Failed' badge that reads
    like the device is broken."""
    return {
        "target_id": target.get("target_id"),
        "host": str(target.get("host") or ""),
        "label": target.get("label"),
        "status": "skipped",
        "code": code,
        "error": code,  # legacy field mirrors the code, as in _fetch_one._fail
    }


def fetch_all(
    targets: list[dict[str, Any]],
    *,
    ssh_timeout: int = 30,
    time_budget: int = 300,
) -> dict[str, Any]:
    """Back up every target, bounded by a wall-clock budget. Never raises.

    Carries the SAME auth circuit breaker as the on-demand test. This is the path
    that matters most for it: `fetch_all` runs unattended every night across the
    whole fleet, so a credential that has just been rotated or mistyped would
    otherwise retry on every device until the time budget ran out — dozens of
    failed logins per night, with nobody watching, against AAA policies that
    typically lock an account after three to five.
    """
    start = time.monotonic()
    key = _redact_key()
    devices: list[dict[str, Any]] = []
    budget_exhausted = False
    breaker = _AuthBreaker()

    for i, target in enumerate(targets):
        if breaker.tripped:
            devices.extend(_skipped(t, "job.stopped_auth_failures") for t in targets[i:])
            break
        if time.monotonic() - start > time_budget:
            budget_exhausted = True
            devices.extend(_skipped(t, "job.budget_exhausted") for t in targets[i:])
            break
        entry = _fetch_one(target, key=key, ssh_timeout=ssh_timeout)
        breaker.record(entry)
        if entry.get("status") == "ok":
            log.info("device config backed up", host=entry["host"], platform=entry.get("platform"))
        else:
            log.warning("device config backup failed", host=entry.get("host"),
                        status=entry.get("status"), error=entry.get("error"))
        devices.append(entry)

    skipped = sum(1 for d in devices if d.get("status") == "skipped")
    if breaker.tripped:
        log.warning("device config pass stopped: consecutive auth rejections",
                    consecutive=breaker.consecutive, skipped=skipped)

    ok = sum(1 for d in devices if d.get("status") == "ok")
    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "devices": devices,
        "stats": {
            "targets": len(targets),
            "ok": ok,
            "errors": sum(1 for d in devices if d.get("status") == "error"),
            "skipped": skipped,
            "elapsed_sec": round(time.monotonic() - start, 2),
            "budget_exhausted": budget_exhausted,
            "stopped_early": breaker.tripped,
        },
    }


def test_targets(
    target_ids: list[int] | None = None,
    *,
    ssh_timeout: int = 20,
    time_budget: int = 900,
    max_workers: int = 4,
) -> dict[str, Any]:
    """On-demand SSH reachability test — a DRY RUN of the nightly backup.

    Runs the identical fetch path with the output discarded, so a pass is a real
    promise about tonight's run rather than a lighter-weight approximation.

    Two behaviors worth knowing about:

    * **Auth circuit breaker.** If the same credential set is rejected by 3
      consecutive devices, the run STOPS. A district-wide password typo must produce
      3 failed logins, not 110 — 110 is how you lock the shared read-only account on
      every switch at once, and take out your own AAA server while you're at it.
      Because devices run concurrently the counter is read between waves, so the
      exact worst case is `max_workers` rejections (one full opening wave) rather
      than 3; every later wave narrows to the remaining headroom. The same breaker
      guards `fetch_all`, where the walk is sequential and the bound is exactly 3.
    * **Bounded concurrency.** School control planes are often aging hardware; four
      parallel sessions is plenty and won't spike CPU across the fleet mid-lesson.
    """
    from concurrent.futures import ThreadPoolExecutor

    start = time.monotonic()
    key = _redact_key()
    targets = load_targets()
    if target_ids:
        wanted = set(target_ids)
        targets = [t for t in targets if t.get("target_id") in wanted]

    results: list[dict[str, Any]] = []
    breaker = _AuthBreaker()

    def _one(target: dict[str, Any]) -> dict[str, Any]:
        return _fetch_one(target, key=key, ssh_timeout=ssh_timeout, discard_output=True)

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, 8))) as pool:
        # Submitted in small waves so the breaker can actually stop the run; a single
        # bulk submit would have every device in flight before the third rejection.
        i = 0
        while i < len(targets):
            if time.monotonic() - start > time_budget:
                results.extend(_skipped(t, "job.budget_exhausted") for t in targets[i:])
                break
            if breaker.tripped:
                results.extend(_skipped(t, "job.stopped_auth_failures") for t in targets[i:])
                break

            # Shrink the wave once the counter is armed. The breaker can only be
            # consulted BETWEEN waves, so a fixed-width wave launched at two strikes
            # would land `max_workers` rejections against a threshold of 3.
            #
            # Clamping only when consecutive > 0 keeps a healthy fleet at full
            # concurrency (the common case, and the one worth being fast). The
            # residual worst case is the FIRST wave rejecting all at once —
            # `max_workers` rejections, not the fleet — after which the run stops.
            width = max_workers if breaker.consecutive == 0 else min(max_workers, breaker.headroom())
            wave = list(pool.map(_one, targets[i : i + width]))
            for entry in wave:
                breaker.record(entry)
            results.extend(wave)
            i += width

    stopped_early = breaker.tripped
    if stopped_early:
        log.warning("device ssh test stopped: consecutive auth rejections",
                    consecutive=breaker.consecutive)

    passed = sum(1 for r in results if r.get("status") == "ok")
    return {
        "tested_at": datetime.now(UTC).isoformat(),
        "devices": results,
        "stats": {
            "targets": len(targets),
            "passed": passed,
            "failed": sum(1 for r in results if r.get("status") == "error"),
            "skipped": sum(1 for r in results if r.get("status") == "skipped"),
            "elapsed_sec": round(time.monotonic() - start, 2),
            "stopped_early": stopped_early,
        },
    }


def collect_and_store(settings: Any) -> None:
    """Gated periodic backup for the poll loop. No-op unless the feature is on,
    targets exist, and the last artifact is older than the configured interval. The
    interval gate reads the artifact's own `collected_at`, so it survives a collector
    restart (unlike a monotonic in-memory timer)."""
    if not getattr(settings, "device_config_enabled", False):
        return
    targets = load_targets()
    if not targets:
        return
    existing = load()
    if existing is not None:
        age = _age_sec(existing.get("collected_at"))
        if age is not None and age < settings.device_config_interval:
            return  # backed up recently enough
    # Run the pass under a HARD wall in a daemon thread so a pathological device that
    # slips past netmiko's per-device timeouts can NEVER wedge the poll loop — which
    # also runs the scans + uploads and is the channel the disable kill-switch rides
    # on. The cooperative time_budget is the primary control; this is the backstop.
    box: dict[str, Any] = {}

    def _run() -> None:
        box["result"] = fetch_all(
            targets,
            ssh_timeout=settings.device_config_ssh_timeout,
            time_budget=settings.device_config_time_budget,
        )

    worker = threading.Thread(target=_run, name="device-config-backup", daemon=True)
    worker.start()
    worker.join(settings.device_config_time_budget + 60)
    if worker.is_alive():
        log.warning("device config pass exceeded hard deadline; skipping this cycle",
                    budget=settings.device_config_time_budget)
        return
    if "result" in box:
        _store(box["result"])


# ---------------------------------------------------------------------------
# Artifact + target-file IO
# ---------------------------------------------------------------------------


def load() -> dict[str, Any] | None:
    """Read the last-written artifact (for the bundle + the interval gate)."""
    try:
        return json.loads(ARTIFACT_FILE.read_text())
    except FileNotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001 — a corrupt file shouldn't wedge bundling
        log.warning("could not read device config artifact", error=str(exc))
        return None


def load_targets() -> list[dict[str, Any]]:
    """Read the 0600 target list check-in wrote from the dashboard push."""
    try:
        data = json.loads(TARGETS_FILE.read_text())
        return data if isinstance(data, list) else []
    except FileNotFoundError:
        return []
    except Exception as exc:  # noqa: BLE001
        log.warning("could not read device config targets", error=str(exc))
        return []


def _store(result: dict[str, Any]) -> None:
    """Write the artifact (0644 — it holds only REDACTED config, no plaintext
    secrets — so the bundle builder reads it like the other box-global artifacts)."""
    try:
        ARTIFACT_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = ARTIFACT_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(result))
        os.replace(str(tmp), str(ARTIFACT_FILE))
    except Exception as exc:  # noqa: BLE001
        log.warning("could not write device config artifact", error=str(exc))


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
