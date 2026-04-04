"""Tests for the passive service banner parser."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from leetha.capture.protocols.banner import parse_service_banner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet(src_ip, src_port, dst_ip, dst_port, payload_bytes):
    """Create a mock scapy packet."""
    pkt = MagicMock()

    ip = MagicMock()
    ip.src = src_ip
    ip.dst = dst_ip

    tcp = MagicMock()
    tcp.sport = src_port
    tcp.dport = dst_port

    raw = MagicMock()
    raw.load = payload_bytes

    # scapy uses `in` operator for layer checking
    layers = {"IP": ip, "TCP": tcp, "Raw": raw}
    pkt.__contains__ = lambda self, layer: layer.__name__ in layers
    pkt.__getitem__ = lambda self, layer: layers[layer.__name__]
    pkt.src = "aa:bb:cc:dd:ee:ff"
    pkt.dst = "11:22:33:44:55:66"

    return pkt


def _make_packet_no_raw(src_ip, src_port, dst_ip, dst_port):
    """Create a mock scapy packet without a Raw layer."""
    pkt = MagicMock()

    ip = MagicMock()
    ip.src = src_ip
    ip.dst = dst_ip

    tcp = MagicMock()
    tcp.sport = src_port
    tcp.dport = dst_port

    layers = {"IP": ip, "TCP": tcp}
    pkt.__contains__ = lambda self, layer: layer.__name__ in layers
    pkt.__getitem__ = lambda self, layer: layers[layer.__name__]
    pkt.src = "aa:bb:cc:dd:ee:ff"
    pkt.dst = "11:22:33:44:55:66"

    return pkt


def _make_packet_no_ip():
    """Create a mock scapy packet without an IP layer."""
    pkt = MagicMock()

    tcp = MagicMock()
    tcp.sport = 22
    tcp.dport = 54321

    layers = {"TCP": tcp}
    pkt.__contains__ = lambda self, layer: layer.__name__ in layers
    pkt.__getitem__ = lambda self, layer: layers[layer.__name__]
    pkt.src = "aa:bb:cc:dd:ee:ff"
    pkt.dst = "11:22:33:44:55:66"

    return pkt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBannerParser:
    def test_ssh_banner(self):
        """SSH banner from server port 22 -> CapturedPacket with service=ssh."""
        payload = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
        pkt = _make_packet("10.0.0.1", 22, "10.0.0.100", 54321, payload)

        result = parse_service_banner(pkt)

        assert result is not None
        assert result.protocol == "service_banner"
        assert result.ip_addr == "10.0.0.1"
        assert result.target_ip == "10.0.0.100"
        assert result.hw_addr == "aa:bb:cc:dd:ee:ff"
        assert result.target_hw == "11:22:33:44:55:66"
        assert result.fields["service"] == "ssh"
        assert result.fields["server_port"] == 22
        assert result.fields["banner_source"] == "server_greeting"

    def test_non_watched_port_returns_none(self):
        """Packet from a non-watched port -> None."""
        payload = b"SSH-2.0-OpenSSH_9.2p1\r\n"
        pkt = _make_packet("10.0.0.1", 8080, "10.0.0.100", 54321, payload)

        result = parse_service_banner(pkt)

        assert result is None

    def test_mysql_greeting(self):
        """MySQL greeting from port 3306 -> CapturedPacket with service=mysql."""
        # Build a minimal MySQL greeting: 3-byte length + seq=0 + proto_ver=0x0A + version string
        version_str = b"8.0.33"
        # length of payload after the 4-byte header
        body_len = 1 + len(version_str) + 1  # proto_ver + version + null
        length_bytes = body_len.to_bytes(3, "little")
        payload = length_bytes + b"\x00" + b"\x0a" + version_str + b"\x00"

        pkt = _make_packet("10.0.0.5", 3306, "10.0.0.100", 54321, payload)

        result = parse_service_banner(pkt)

        assert result is not None
        assert result.protocol == "service_banner"
        assert result.fields["service"] == "mysql"
        assert result.fields["version"] is not None
        assert result.fields["server_port"] == 3306

    def test_no_payload_returns_none(self):
        """SYN packet with no Raw layer -> None."""
        pkt = _make_packet_no_raw("10.0.0.1", 22, "10.0.0.100", 54321)

        result = parse_service_banner(pkt)

        assert result is None

    def test_non_matching_payload_returns_none(self):
        """Non-matching payload from a watched port -> None."""
        payload = b"\x00\x01\x02\x03random garbage that matches nothing"
        pkt = _make_packet("10.0.0.1", 22, "10.0.0.100", 54321, payload)

        result = parse_service_banner(pkt)

        assert result is None

    def test_no_ip_layer_returns_none(self):
        """Packet without IP layer -> None."""
        pkt = _make_packet_no_ip()

        result = parse_service_banner(pkt)

        assert result is None
