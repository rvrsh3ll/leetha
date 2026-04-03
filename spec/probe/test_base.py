"""Tests for new probe plugin base class and discovery."""
from unittest.mock import MagicMock
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity


class TestServiceProbe:
    def test_cannot_instantiate_abstract(self):
        """ServiceProbe is abstract -- can't instantiate directly."""
        import pytest
        with pytest.raises(TypeError):
            ServiceProbe()

    def test_subclass_with_identify(self):
        """A concrete subclass with identify() should instantiate."""
        class TestProbe(ServiceProbe):
            name = "test"
            protocol = "tcp"
            default_ports = [9999]

            def identify(self, conn):
                return ServiceIdentity(service="test", certainty=100)

        probe = TestProbe()
        assert probe.name == "test"
        assert probe.default_ports == [9999]

    def test_identify_returns_identity(self):
        class EchoProbe(ServiceProbe):
            name = "echo"
            protocol = "tcp"
            default_ports = [7]

            def identify(self, conn):
                data = conn.read()
                if data:
                    return ServiceIdentity(service="echo", certainty=90, banner=data.decode())
                return None

        probe = EchoProbe()
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"hello"
        conn = ServiceConnection(mock_sock, "127.0.0.1", 7)
        result = probe.identify(conn)
        assert result is not None
        assert result.service == "echo"
        assert result.certainty == 90

    def test_repr(self):
        class MyProbe(ServiceProbe):
            name = "myservice"
            default_ports = [1234]
            def identify(self, conn): return None

        assert "myservice" in repr(MyProbe())
