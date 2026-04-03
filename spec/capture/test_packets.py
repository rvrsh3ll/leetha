"""Tests for CapturedPacket model."""
from datetime import datetime
from leetha.capture.packets import CapturedPacket


class TestCapturedPacket:
    def test_defaults(self):
        p = CapturedPacket(protocol="arp", hw_addr="aa:bb:cc:dd:ee:ff", ip_addr="192.168.1.1")
        assert p.protocol == "arp"
        assert p.hw_addr == "aa:bb:cc:dd:ee:ff"
        assert p.ip_addr == "192.168.1.1"
        assert p.target_ip is None
        assert p.target_hw is None
        assert p.fields == {}
        assert p.raw is None
        assert p.interface is None
        assert isinstance(p.captured_at, datetime)

    def test_full_packet(self):
        p = CapturedPacket(
            protocol="tcp_syn",
            hw_addr="aa:bb:cc:dd:ee:ff",
            ip_addr="192.168.1.100",
            target_ip="10.0.0.1",
            target_hw="11:22:33:44:55:66",
            fields={"ttl": 64, "window_size": 29200, "mss": 1460},
            raw=b"\x00\x01\x02",
            interface="eth0",
            network="192.168.1.0/24",
        )
        assert p.target_ip == "10.0.0.1"
        assert p.fields["ttl"] == 64
        assert p.raw == b"\x00\x01\x02"
        assert p.interface == "eth0"

    def test_get_shorthand(self):
        p = CapturedPacket(
            protocol="dhcpv4", hw_addr="aa:bb:cc:dd:ee:ff", ip_addr="0.0.0.0",
            fields={"hostname": "desktop-01", "opt55": "1,3,6,15"},
        )
        assert p.get("hostname") == "desktop-01"
        assert p.get("opt55") == "1,3,6,15"
        assert p.get("missing") is None
        assert p.get("missing", "default") == "default"

    def test_lldp_packet(self):
        p = CapturedPacket(
            protocol="lldp",
            hw_addr="00:1a:2b:3c:4d:5e",
            ip_addr="",
            fields={
                "system_name": "core-switch.lab",
                "system_description": "Cisco IOS 15.2",
                "capabilities": ["bridge", "router"],
                "management_ip": "192.168.1.1",
            },
        )
        assert p.protocol == "lldp"
        assert p.get("capabilities") == ["bridge", "router"]
