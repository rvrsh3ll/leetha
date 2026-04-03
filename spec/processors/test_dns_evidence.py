"""Tests for DNS vendor evidence extraction."""
from leetha.processors.names import NameResolutionProcessor
from leetha.capture.packets import CapturedPacket
from leetha.evidence.models import Evidence


class TestDnsVendorEvidence:
    def setup_method(self):
        self.processor = NameResolutionProcessor()

    def test_apple_domain_produces_vendor_evidence(self):
        pkt = CapturedPacket(protocol="dns", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.100",
                             fields={"query_name": "icloud.com", "query_type": 1})
        result = self.processor.analyze(pkt)
        assert any(e.vendor == "Apple" for e in result)

    def test_microsoft_domain_produces_platform_evidence(self):
        pkt = CapturedPacket(protocol="dns", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.100",
                             fields={"query_name": "update.microsoft.com", "query_type": 1})
        result = self.processor.analyze(pkt)
        assert any(e.platform == "Windows" for e in result)

    def test_unknown_domain_no_vendor_evidence(self):
        pkt = CapturedPacket(protocol="dns", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.100",
                             fields={"query_name": "example.com", "query_type": 1})
        result = self.processor.analyze(pkt)
        assert not any(e.vendor for e in result)

    def test_dns_evidence_has_query_in_raw(self):
        pkt = CapturedPacket(protocol="dns", hw_addr="aa:bb:cc:dd:ee:ff",
                             ip_addr="192.168.1.100",
                             fields={"query_name": "gs.apple.com", "query_type": 1})
        result = self.processor.analyze(pkt)
        assert any("gs.apple.com" in str(e.raw) for e in result)
