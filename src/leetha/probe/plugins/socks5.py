"""SOCKS5 probe plugin — SOCKS version 5 proxy detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SOCKS5ProbePlugin(ServiceProbe):
    name = "socks5"
    protocol = "tcp"
    default_ports = [1080, 1081]

    AUTH_METHODS = {
        0x00: "no_auth",
        0x01: "gssapi",
        0x02: "username_password",
        0xFF: "no_acceptable",
    }

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # SOCKS5 greeting
            # Version: 0x05, Number of methods: 0x01, Method: 0x00 (no auth)
            greeting = bytes([0x05, 0x01, 0x00])

            conn.write(greeting)
            data = conn.read(4096)

            if not data or len(data) < 2:
                return None

            # SOCKS5 response: version + selected method
            version = data[0]
            method = data[1]

            if version != 0x05:
                return None

            metadata: dict = {
                "selected_method": method,
                "auth_method": self.AUTH_METHODS.get(method, f"unknown({method})"),
            }

            return ServiceIdentity(
                service="socks5",
                certainty=85,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
