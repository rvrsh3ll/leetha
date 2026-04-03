"""Tests for Evidence and Verdict models."""
from datetime import datetime
from leetha.evidence.models import Evidence, Verdict


class TestEvidence:
    def test_defaults(self):
        e = Evidence(source="lldp", method="exact", certainty=0.9)
        assert e.source == "lldp"
        assert e.method == "exact"
        assert e.certainty == 0.9
        assert e.category is None
        assert e.vendor is None
        assert e.platform is None
        assert e.raw == {}
        assert isinstance(e.observed_at, datetime)

    def test_optional_fields(self):
        e = Evidence(
            source="cdp", method="exact", certainty=0.92,
            category="switch", vendor="Cisco", platform="IOS-XE",
            platform_version="16.12.4", model="WS-C3850-24T",
            hostname="core-sw01",
        )
        assert e.category == "switch"
        assert e.vendor == "Cisco"
        assert e.platform == "IOS-XE"
        assert e.platform_version == "16.12.4"
        assert e.model == "WS-C3850-24T"
        assert e.hostname == "core-sw01"

    def test_to_dict(self):
        e = Evidence(source="arp", method="heuristic", certainty=0.5)
        d = e.to_dict()
        assert d["source"] == "arp"
        assert d["method"] == "heuristic"
        assert d["certainty"] == 0.5
        assert isinstance(d["observed_at"], str)  # ISO format string

    def test_weight_property(self):
        e = Evidence(source="lldp", method="exact", certainty=0.95)
        assert e.weight == 0.95

    def test_raw_data_preserved(self):
        raw = {"system_name": "switch01", "capabilities": ["bridge"]}
        e = Evidence(source="lldp", method="exact", certainty=0.9, raw=raw)
        assert e.raw["system_name"] == "switch01"


class TestVerdict:
    def test_defaults(self):
        v = Verdict(hw_addr="aa:bb:cc:dd:ee:ff")
        assert v.hw_addr == "aa:bb:cc:dd:ee:ff"
        assert v.category is None
        assert v.certainty == 0
        assert v.evidence_chain == []
        assert isinstance(v.computed_at, datetime)

    def test_full_verdict(self):
        evidence = [
            Evidence(source="lldp", method="exact", certainty=0.9, vendor="Cisco"),
            Evidence(source="cdp", method="exact", certainty=0.92, platform="IOS"),
        ]
        v = Verdict(
            hw_addr="aa:bb:cc:dd:ee:ff",
            category="switch", vendor="Cisco",
            platform="IOS", certainty=91,
            evidence_chain=evidence,
        )
        assert v.category == "switch"
        assert v.vendor == "Cisco"
        assert len(v.evidence_chain) == 2

    def test_to_dict(self):
        e = Evidence(source="arp", method="heuristic", certainty=0.5)
        v = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", certainty=50, evidence_chain=[e])
        d = v.to_dict()
        assert d["hw_addr"] == "aa:bb:cc:dd:ee:ff"
        assert d["certainty"] == 50
        assert len(d["evidence_chain"]) == 1
        assert d["evidence_chain"][0]["source"] == "arp"
        assert isinstance(d["computed_at"], str)

    def test_is_classified_true(self):
        v = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", category="router")
        assert v.is_classified is True

    def test_is_classified_false(self):
        v = Verdict(hw_addr="aa:bb:cc:dd:ee:ff")
        assert v.is_classified is False

    def test_is_classified_vendor_only(self):
        v = Verdict(hw_addr="aa:bb:cc:dd:ee:ff", vendor="Ubiquiti")
        assert v.is_classified is True
