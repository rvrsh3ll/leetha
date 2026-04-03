"""Tests for ServiceIdentity."""
from leetha.probe.identity import ServiceIdentity


class TestServiceIdentity:
    def test_defaults(self):
        si = ServiceIdentity(service="ssh")
        assert si.service == "ssh"
        assert si.version is None
        assert si.banner is None
        assert si.certainty == 0
        assert si.metadata == {}
        assert si.tls_detected is False

    def test_full_identity(self):
        si = ServiceIdentity(
            service="http", version="1.24.0",
            banner="Server: nginx/1.24.0",
            certainty=95,
            metadata={"server": "nginx", "os_hint": "Linux"},
            tls_detected=True,
        )
        assert si.version == "1.24.0"
        assert si.certainty == 95
        assert si.tls_detected is True
        assert si.metadata["os_hint"] == "Linux"
