"""Tests for DNS-based NTP vendor inference."""
import pytest
from leetha.processors.names import NameResolutionProcessor, _NTP_VENDOR_MAP
from leetha.capture.packets import CapturedPacket


def _dns_packet(query_name: str) -> CapturedPacket:
    return CapturedPacket(
        protocol="dns",
        hw_addr="aa:bb:cc:dd:ee:ff",
        ip_addr="192.168.1.10",
        fields={"query_name": query_name, "query_type": 1, "query_type_name": "A"},
    )


def test_apple_ntp_detected():
    proc = NameResolutionProcessor()
    evidence = proc.analyze(_dns_packet("time.apple.com"))
    ntp_hints = [e for e in evidence if e.source == "dns_ntp_hint"]
    assert len(ntp_hints) == 1
    assert ntp_hints[0].vendor == "Apple"
    assert ntp_hints[0].platform == "iOS/macOS"


def test_windows_ntp_detected():
    proc = NameResolutionProcessor()
    evidence = proc.analyze(_dns_packet("time.windows.com"))
    ntp_hints = [e for e in evidence if e.source == "dns_ntp_hint"]
    assert len(ntp_hints) == 1
    assert ntp_hints[0].vendor == "Microsoft"
    assert ntp_hints[0].platform == "Windows"


def test_ubiquiti_ntp_detected():
    proc = NameResolutionProcessor()
    evidence = proc.analyze(_dns_packet("time.ui.com"))
    ntp_hints = [e for e in evidence if e.source == "dns_ntp_hint"]
    assert len(ntp_hints) == 1
    assert ntp_hints[0].vendor == "Ubiquiti"


def test_generic_dns_no_ntp_hint():
    proc = NameResolutionProcessor()
    evidence = proc.analyze(_dns_packet("www.google.com"))
    ntp_hints = [e for e in evidence if e.source == "dns_ntp_hint"]
    assert len(ntp_hints) == 0


def test_ntp_vendor_map_has_entries():
    assert len(_NTP_VENDOR_MAP) >= 15
    assert "time.apple.com" in _NTP_VENDOR_MAP
    assert "time.windows.com" in _NTP_VENDOR_MAP
