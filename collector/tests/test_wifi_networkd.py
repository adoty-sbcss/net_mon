"""WIFI-1 networkd backend: the two pure generators in lib/wifi.sh.

The wpa_supplicant config carries the secrets and the .network file carries the
routes-off contract, so both are pinned here. The join itself is exercised against
simulated radios by .github/workflows/wifi-hwsim.yml.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_LIB = Path(__file__).resolve().parents[2] / "lib" / "wifi.sh"


def _bash() -> str:
    if sys.platform == "win32":
        git = shutil.which("git")
        candidates = [d / "bin" / "bash.exe" for d in Path(git).parents] if git else []
        found = next((str(c) for c in candidates if c.exists()), None)
    else:
        found = shutil.which("bash")
    if not found:
        pytest.skip("bash is required")
    return found


def _call(fn: str, *args: str) -> tuple[int, str]:
    # Arguments travel through the environment, so a secret with quotes or a newline
    # reaches the function byte for byte.
    env = dict(os.environ, NETMON_WPA_RUN_DIR="/run/netmon-wifi")
    names = []
    for i, a in enumerate(args):
        env[f"A{i}"] = a
        names.append(f'"$A{i}"')
    code = f'warn() {{ :; }}; ok() {{ :; }}; . "{_LIB.as_posix()}"; {fn} {" ".join(names)}'
    out = subprocess.run([_bash(), "-c", code], capture_output=True, env=env)
    return out.returncode, out.stdout.decode()


def _hex(s: str) -> str:
    return s.encode().hex()


def test_psk_passphrase_is_quoted_and_ssid_is_hex() -> None:
    ssid = 'Staff "5G"'
    rc, conf = _call("wifi_wpa_conf_content", ssid, "psk", "", 'pa ss"word!')
    assert rc == 0
    assert f"\tssid={_hex(ssid)}\n" in conf
    assert '\tpsk="pa ss"word!"\n' in conf and "\tkey_mgmt=WPA-PSK\n" in conf
    assert "ctrl_interface=/run/netmon-wifi/ctrl\n" in conf


def test_raw_64_hex_psk_goes_in_bare() -> None:
    key = "ab" * 32
    rc, conf = _call("wifi_wpa_conf_content", "Net", "psk", "", key)
    assert rc == 0 and f"\tpsk={key}\n" in conf


@pytest.mark.parametrize("secret", ["short", "x" * 64, "line\nbreak123", "tab\there123", "cafécafé"])
def test_unusable_passphrases_are_refused(secret: str) -> None:
    assert _call("wifi_wpa_conf_content", "Net", "psk", "", secret)[0] == 1


def test_peap_identity_and_password_are_hex_never_quoted() -> None:
    ident, pw = 'svc"netmon', 'p"w\nx'
    rc, conf = _call("wifi_wpa_conf_content", "Staff", "peap", ident, pw)
    assert rc == 0
    assert "\teap=PEAP\n" in conf and "\tkey_mgmt=WPA-EAP\n" in conf
    assert f"\tidentity={_hex(ident)}\n" in conf
    assert f"\tpassword={_hex(pw)}\n" in conf
    assert 'phase2="auth=MSCHAPV2"' in conf
    assert conf.count("\n}") == 1  # the newline in the password could not end the block


def test_peap_without_a_username_is_refused() -> None:
    assert _call("wifi_wpa_conf_content", "Staff", "peap", "", "pw")[0] == 1


def test_open_network() -> None:
    rc, conf = _call("wifi_wpa_conf_content", "Guest", "open")
    assert rc == 0 and "\tkey_mgmt=NONE\n" in conf and "psk" not in conf


def test_network_unit_takes_an_address_and_nothing_else() -> None:
    rc, unit = _call("wifi_networkd_unit_content", "wlo1")
    assert rc == 0
    assert "[Match]\nName=wlo1\n" in unit and "DHCP=ipv4\n" in unit
    for line in ("UseGateway=no", "UseRoutes=no", "UseDNS=no", "UseDomains=no",
                 "RequiredForOnline=no", "DNSDefaultRoute=no", "IPv6AcceptRA=no"):
        assert f"{line}\n" in unit, line
