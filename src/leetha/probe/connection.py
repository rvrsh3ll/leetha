"""Service connection wrapper for probe plugins.

ServiceConnection provides a clean interface over raw sockets, handling
common patterns like read/write/exchange so plugins don't manage sockets directly.
"""
from __future__ import annotations

import socket
import ssl


class ServiceConnection:
    """Protocol-aware socket wrapper for service probing."""

    def __init__(self, sock: socket.socket, host: str, port: int):
        self.host = host
        self.port = port
        self._sock = sock

    def read(self, size: int = 4096) -> bytes:
        """Read up to *size* bytes from the connection."""
        return self._sock.recv(size)

    def write(self, data: bytes) -> None:
        """Send data to the connection."""
        self._sock.sendall(data)

    def read_line(self) -> str:
        """Read a line of text (convenience for banner protocols)."""
        data = self.read(4096)
        return data.decode("utf-8", errors="replace").strip()

    def exchange(self, request: bytes, size: int = 4096) -> bytes:
        """Send a request and return the response."""
        self.write(request)
        return self.read(size)

    def upgrade_tls(self, server_hostname: str | None = None) -> None:
        """Wrap the connection in TLS."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._sock = ctx.wrap_socket(
            self._sock, server_hostname=server_hostname or self.host,
        )

    def set_timeout(self, seconds: float) -> None:
        """Set socket timeout."""
        self._sock.settimeout(seconds)

    @property
    def raw_socket(self) -> socket.socket:
        """Access the underlying socket (escape hatch for complex protocols)."""
        return self._sock
