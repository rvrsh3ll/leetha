"""Tests for NTP parser."""
import struct
import pytest
from leetha.capture.protocols.ntp import parse_ntp


def _make_ntp_payload(mode=3, stratum=2, ref_id=b"\xc0\xa8\x01\x01"):
    """Build a minimal 48-byte NTP packet."""
    # Byte 0: LI=0, VN=4, Mode
    byte0 = (0 << 6) | (4 << 3) | mode
    payload = bytearray(48)
    payload[0] = byte0
    payload[1] = stratum
    payload[12:16] = ref_id
    return bytes(payload)


def test_parse_ntp_client():
    from unittest.mock import MagicMock
    ntp_data = _make_ntp_payload(mode=3, stratum=0)

    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.src = "aa:bb:cc:dd:ee:ff"

    udp_mock = MagicMock()
    udp_mock.dport = 123
    udp_mock.sport = 50000
    udp_mock.payload = ntp_data

    ip_mock = MagicMock()
    ip_mock.src = "192.168.1.10"
    ip_mock.dst = "129.6.15.28"

    def getitem(self, key):
        from scapy.layers.inet import IP, UDP
        if key is UDP:
            return udp_mock
        if key is IP:
            return ip_mock
        return MagicMock()

    pkt.__getitem__ = getitem
    result = parse_ntp(pkt)
    assert result is not None
    assert result.fields["mode"] == "client"


def test_parse_ntp_server_stratum1():
    from unittest.mock import MagicMock
    ntp_data = _make_ntp_payload(mode=4, stratum=1, ref_id=b"GPS\x00")

    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.src = "aa:bb:cc:dd:ee:ff"

    udp_mock = MagicMock()
    udp_mock.dport = 50000
    udp_mock.sport = 123
    udp_mock.payload = ntp_data

    ip_mock = MagicMock()
    ip_mock.src = "192.168.1.1"
    ip_mock.dst = "192.168.1.10"

    def getitem(self, key):
        from scapy.layers.inet import IP, UDP
        if key is UDP:
            return udp_mock
        if key is IP:
            return ip_mock
        return MagicMock()

    pkt.__getitem__ = getitem
    result = parse_ntp(pkt)
    assert result is not None
    assert result.fields["mode"] == "server"
    assert result.fields["stratum"] == 1
    assert result.fields["reference_id"] == "GPS"


def test_parse_ntp_too_short():
    from unittest.mock import MagicMock
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.src = "aa:bb:cc:dd:ee:ff"

    udp_mock = MagicMock()
    udp_mock.dport = 123
    udp_mock.sport = 50000
    udp_mock.payload = b"\x00" * 10  # Too short

    def getitem(self, key):
        from scapy.layers.inet import IP, UDP
        if key is UDP:
            return udp_mock
        return MagicMock()

    pkt.__getitem__ = getitem
    result = parse_ntp(pkt)
    assert result is None


def test_parse_ntp_wrong_port():
    from unittest.mock import MagicMock
    pkt = MagicMock()
    pkt.haslayer.return_value = True

    udp_mock = MagicMock()
    udp_mock.dport = 80
    udp_mock.sport = 12345

    def getitem(self, key):
        from scapy.layers.inet import IP, UDP
        if key is UDP:
            return udp_mock
        return MagicMock()

    pkt.__getitem__ = getitem
    result = parse_ntp(pkt)
    assert result is None
