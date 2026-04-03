"""Tests for NetworkDiscoveryProcessor."""
from leetha.processors.network import NetworkDiscoveryProcessor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


class TestNetworkDiscoveryProcessor:
    def setup_method(self):
        self.processor = NetworkDiscoveryProcessor()

    def test_arp_produces_evidence(self):
        pkt = CapturedPacket(protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.1", fields={"op": 1})
        result = self.processor.analyze(pkt)
        assert len(result) >= 1
        assert all(isinstance(e, Evidence) for e in result)

    def test_dhcpv4_with_hostname(self):
        pkt = CapturedPacket(protocol="dhcpv4", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.100",
                             fields={"hostname": "DESKTOP-ABC", "opt55": "1,3,6,15"})
        result = self.processor.analyze(pkt)
        assert any(e.hostname == "DESKTOP-ABC" for e in result)

    def test_icmpv6_router_advertisement(self):
        pkt = CapturedPacket(protocol="icmpv6", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="fe80::1",
                             fields={"icmpv6_type": "router_advertisement", "hop_limit": 64})
        result = self.processor.analyze(pkt)
        assert any(e.category == "router" for e in result)

    def test_unknown_protocol_returns_empty(self):
        pkt = CapturedPacket(protocol="unknown", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.1")
        result = self.processor.analyze(pkt)
        assert result == []
