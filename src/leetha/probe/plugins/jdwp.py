"""JDWP probe plugin — Java Debug Wire Protocol handshake detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class JDWPProbePlugin(ServiceProbe):
    name = "jdwp"
    protocol = "tcp"
    default_ports = [5005, 8000]

    _HANDSHAKE = b"JDWP-Handshake"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # JDWP servers send "JDWP-Handshake" immediately on connection
            # or after receiving "JDWP-Handshake" from the client
            data = conn.read(1024)

            if data and self._HANDSHAKE in data:
                return ServiceIdentity(
                    service="jdwp",
                    certainty=95,
                    banner=data.decode("utf-8", errors="replace"),
                    metadata={"handshake": True},
                )

            # If no banner, send handshake and check for echo
            conn.write(self._HANDSHAKE)
            data = conn.read(1024)
            if not data:
                return None

            if self._HANDSHAKE in data:
                return ServiceIdentity(
                    service="jdwp",
                    certainty=95,
                    banner=data.decode("utf-8", errors="replace"),
                    metadata={"handshake": True},
                )

            return None
        except (socket.timeout, OSError):
            return None
