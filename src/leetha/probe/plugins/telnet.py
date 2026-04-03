"""Telnet probe plugin — banner grab with IAC negotiation."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TelnetProbePlugin(ServiceProbe):
    name = "telnet"
    protocol = "tcp"
    default_ports = [23, 2323]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None
            # Strip IAC sequences (0xFF followed by 2 bytes)
            cleaned = bytearray()
            i = 0
            while i < len(data):
                if data[i] == 0xFF and i + 2 < len(data):
                    i += 3
                else:
                    cleaned.append(data[i])
                    i += 1
            banner = bytes(cleaned).decode("utf-8", errors="replace").strip()
            # Telnet sends IAC sequences or a login prompt
            if data[0:1] == b'\xff' or any(kw in banner.lower() for kw in ("login", "user", "password", "welcome")):
                return ServiceIdentity(service="telnet", banner=banner if banner else None, certainty=80, metadata={"has_iac": data[0:1] == b'\xff'})
            return None
        except (socket.timeout, OSError):
            return None
