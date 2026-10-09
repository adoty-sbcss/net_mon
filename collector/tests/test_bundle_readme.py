"""The README zipped into every bundle must describe the sensor that wrote it.

It is read by whoever opens a bundle, long after the fact. Two of its claims
had gone false without anything noticing: that bundles go to an SFTP server
(they are uploaded over HTTPS; the collector has no SFTP code), and that SNMP
polling is off by default (it is on, and idle until a community is set).
"""
from __future__ import annotations

from collector import prompts
from collector.config import Settings

READMES = {
    "single-scan": prompts.CLAUDE_BUNDLE_README,
    "hourly": prompts.CLAUDE_BUNDLE_README_HOURLY,
}


def test_bundle_readmes_do_not_claim_sftp() -> None:
    for name, text in READMES.items():
        assert "sftp" not in text.lower(), name
    assert "uploaded\nover HTTPS" in prompts.CLAUDE_BUNDLE_README_HOURLY


def test_bundle_readme_snmp_claim_matches_the_real_default() -> None:
    # If this default ever flips, the sentence has to flip with it.
    assert Settings.model_fields["snmp_enabled"].default is True
    assert Settings.model_fields["snmp_communities"].default == ""
    text = prompts.CLAUDE_BUNDLE_README
    assert "off by default" not in text
    assert "enabled by default but does nothing until" in text
