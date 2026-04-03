"""Tests for ServiceConnection."""
from unittest.mock import MagicMock
from leetha.probe.connection import ServiceConnection


class TestServiceConnection:
    def test_read(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        conn = ServiceConnection(mock_sock, "192.168.1.1", 22)
        data = conn.read()
        assert data == b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_sock.recv.assert_called_once_with(4096)

    def test_write(self):
        mock_sock = MagicMock()
        conn = ServiceConnection(mock_sock, "192.168.1.1", 80)
        conn.write(b"GET / HTTP/1.0\r\n\r\n")
        mock_sock.sendall.assert_called_once_with(b"GET / HTTP/1.0\r\n\r\n")

    def test_read_line(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"220 mail.example.com ESMTP\r\n"
        conn = ServiceConnection(mock_sock, "192.168.1.1", 25)
        line = conn.read_line()
        assert line == "220 mail.example.com ESMTP"

    def test_exchange(self):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"PONG"
        conn = ServiceConnection(mock_sock, "192.168.1.1", 6379)
        response = conn.exchange(b"PING\r\n")
        mock_sock.sendall.assert_called_once_with(b"PING\r\n")
        assert response == b"PONG"

    def test_host_and_port(self):
        mock_sock = MagicMock()
        conn = ServiceConnection(mock_sock, "10.0.0.1", 443)
        assert conn.host == "10.0.0.1"
        assert conn.port == 443

    def test_raw_socket_access(self):
        mock_sock = MagicMock()
        conn = ServiceConnection(mock_sock, "10.0.0.1", 22)
        assert conn.raw_socket is mock_sock

    def test_set_timeout(self):
        mock_sock = MagicMock()
        conn = ServiceConnection(mock_sock, "10.0.0.1", 22)
        conn.set_timeout(5.0)
        mock_sock.settimeout.assert_called_once_with(5.0)
