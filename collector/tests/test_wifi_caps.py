"""WIFI-1 radio capability probe: `iw phy info` / `iw reg get` parsing."""
from __future__ import annotations

from collector.discovery import wifi_caps

# Trimmed real-shape output of an Intel AX201 under the world domain (older iw: integer
# MHz, "passive scanning" wording) — bands 1 and 2, modes, scan limit.
_PHY_OLD = """Wiphy phy0
\twiphy index: 0
\tmax # scan SSIDs: 20
\tmax scan IEs length: 422 bytes
\tSupported Ciphers:
\t\t* WEP40 (00-0f-ac:1)
\tAvailable Antennas: TX 0 RX 0
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * AP/VLAN
\t\t * monitor
\t\t * P2P-client
\tBand 1:
\t\tCapabilities: 0x1062
\t\t\tHT20/HT40
\t\tBitrates (non-HT):
\t\t\t* 1.0 Mbps
\t\t\t* 2.0 Mbps (short preamble supported)
\t\tFrequencies:
\t\t\t* 2412 MHz [1] (22.0 dBm)
\t\t\t* 2437 MHz [6] (22.0 dBm)
\t\t\t* 2462 MHz [11] (22.0 dBm)
\t\t\t* 2467 MHz [12] (22.0 dBm) (passive scanning, no IBSS)
\t\t\t* 2484 MHz [14] (disabled)
\tBand 2:
\t\tFrequencies:
\t\t\t* 5180 MHz [36] (22.0 dBm) (passive scanning, no IBSS)
\t\t\t* 5260 MHz [52] (22.0 dBm) (passive scanning, no IBSS, radar detection)
\t\t\t* 5825 MHz [165] (disabled)
\tSupported commands:
\t\t * new_interface
\t\t * set_interface
\tsoftware interface modes (can always be added):
\t\t * AP/VLAN
\t\t * monitor
\tvalid interface combinations:
\t\t * #{ managed } <= 1, #{ AP, P2P-client, P2P-GO } <= 1,
"""

# Newer iw: decimal MHz, "no IR" wording, a 6 GHz band, and no monitor mode.
_PHY_NEW = """Wiphy phy1
\twiphy index: 1
\tmax # scan SSIDs: 4
\tSupported interface modes:
\t\t * managed
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412.0 MHz [1] (20.0 dBm)
\tBand 4:
\t\tFrequencies:
\t\t\t* 5955.0 MHz [1] (no IR)
\t\t\t* 5975.0 MHz [5] (disabled)
\tBand 2:
\t\tFrequencies:
\t\t\t* 5500.0 MHz [100] (24.0 dBm) (no IR, radar detection)
"""


def test_old_iw_output_gives_bands_channels_and_modes() -> None:
    caps = wifi_caps.parse_phy_info(_PHY_OLD)
    assert list(caps["bands"]) == ["2.4GHz", "5GHz"]
    two = caps["bands"]["2.4GHz"]
    assert two["channels"] == [1, 6, 11, 12] and two["disabled"] == 1 and two["no_ir"] == 1
    five = caps["bands"]["5GHz"]
    assert five["channels"] == [36, 52] and five["dfs"] == 1 and five["no_ir"] == 2 and five["disabled"] == 1
    assert caps["monitor"] is True and caps["ap"] is True
    assert caps["max_scan_ssids"] == 20
    # bitrate bullets, ciphers and "Supported commands" items are not modes
    assert "new_interface" not in caps["modes"] and caps["modes"].count("monitor") == 1


def test_new_iw_output_with_6ghz_and_no_monitor() -> None:
    caps = wifi_caps.parse_phy_info(_PHY_NEW)
    assert list(caps["bands"]) == ["2.4GHz", "5GHz", "6GHz"]  # fixed order, whatever iw's
    assert caps["bands"]["6GHz"] == {"channels": [1], "disabled": 1, "dfs": 0, "no_ir": 1}
    assert caps["bands"]["5GHz"]["dfs"] == 1
    assert caps["monitor"] is False and caps["ap"] is False and caps["max_scan_ssids"] == 4


def test_empty_output_is_an_empty_capability_set_not_an_error() -> None:
    caps = wifi_caps.parse_phy_info("")
    assert caps["bands"] == {} and caps["monitor"] is False and caps["max_scan_ssids"] is None


_REG = """global
country 00: DFS-UNSET
\t(2402 - 2472 @ 40), (6, 20), (N/A)
\t(5170 - 5250 @ 80), (6, 20), (N/A), AUTO-BW, PASSIVE-SCAN

phy#1 (self-managed)
country US: DFS-FCC
\t(2402 - 2472 @ 40), (6, 30), (N/A)
"""


def test_reg_prefers_the_phys_self_managed_domain() -> None:
    assert wifi_caps.parse_reg(_REG, 1) == "US"
    assert wifi_caps.parse_reg(_REG, 0) == "00"  # not self-managed: the global domain
    assert wifi_caps.parse_reg(_REG, None) == "00"
    assert wifi_caps.parse_reg("", 0) is None


def test_probe_is_none_without_iw(monkeypatch) -> None:
    monkeypatch.setattr(wifi_caps.shutil, "which", lambda _name: None)
    assert wifi_caps.probe("wlan0") is None
