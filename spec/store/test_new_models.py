"""Tests for new domain model types."""
from datetime import datetime
from leetha.store.models import Host, Finding, Sighting, FindingRule, AlertSeverity


class TestHost:
    def test_defaults(self):
        h = Host(hw_addr="aa:bb:cc:dd:ee:ff")
        assert h.hw_addr == "aa:bb:cc:dd:ee:ff"
        assert h.ip_addr is None
        assert h.disposition == "new"
        assert h.mac_randomized is False
        assert isinstance(h.discovered_at, datetime)

    def test_full_host(self):
        h = Host(
            hw_addr="aa:bb:cc:dd:ee:ff", ip_addr="192.168.1.100",
            disposition="known", mac_randomized=True,
            real_hw_addr="11:22:33:44:55:66",
        )
        assert h.ip_addr == "192.168.1.100"
        assert h.disposition == "known"
        assert h.real_hw_addr == "11:22:33:44:55:66"

    def test_to_dict(self):
        h = Host(hw_addr="aa:bb:cc:dd:ee:ff")
        d = h.to_dict()
        assert d["hw_addr"] == "aa:bb:cc:dd:ee:ff"
        assert isinstance(d["discovered_at"], str)


class TestFinding:
    def test_defaults(self):
        f = Finding(
            hw_addr="aa:bb:cc:dd:ee:ff",
            rule=FindingRule.NEW_HOST,
            severity=AlertSeverity.INFO,
            message="New host discovered",
        )
        assert f.rule == FindingRule.NEW_HOST
        assert f.resolved is False
        assert f.id is None

    def test_all_rules_exist(self):
        assert FindingRule.NEW_HOST == "new_host"
        assert FindingRule.PLATFORM_DRIFT == "platform_drift"
        assert FindingRule.ADDR_CONFLICT == "addr_conflict"
        assert FindingRule.LOW_CERTAINTY == "low_certainty"
        assert FindingRule.STALE_SOURCE == "stale_source"
        assert FindingRule.RANDOMIZED_ADDR == "randomized_addr"
        assert FindingRule.DHCP_ANOMALY == "dhcp_anomaly"


class TestSighting:
    def test_defaults(self):
        s = Sighting(hw_addr="aa:bb:cc:dd:ee:ff", source="arp")
        assert s.source == "arp"
        assert s.payload == {}
        assert s.certainty == 0.0
        assert s.interface is None

    def test_with_data(self):
        s = Sighting(
            hw_addr="aa:bb:cc:dd:ee:ff", source="dhcpv4",
            payload={"hostname": "desktop-01", "opt55": "1,3,6,15"},
            certainty=0.85, interface="eth0", network="192.168.1.0/24",
        )
        assert s.payload["hostname"] == "desktop-01"
        assert s.certainty == 0.85
        assert s.network == "192.168.1.0/24"
