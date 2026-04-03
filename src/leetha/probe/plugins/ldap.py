"""LDAP probe plugin — anonymous bind."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LDAPProbePlugin(ServiceProbe):
    name = "ldap"
    protocol = "tcp"
    default_ports = [389, 636]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # LDAP Simple Bind Request (anonymous)
            bind_request = bytes([
                0x30, 0x0c,  # SEQUENCE
                0x02, 0x01, 0x01,  # MessageID: 1
                0x60, 0x07,  # BindRequest
                0x02, 0x01, 0x03,  # Version: 3
                0x04, 0x00,  # Name: "" (anonymous)
                0x80, 0x00,  # Simple auth: "" (no password)
            ])
            conn.write(bind_request)
            data = conn.read(1024)
            if not data or len(data) < 10:
                return None
            # Check for LDAP response (SEQUENCE tag)
            if data[0] != 0x30:
                return None
            # Look for BindResponse tag (0x61)
            if b'\x61' in data:
                metadata = {"anonymous_bind": True}
                return ServiceIdentity(service="ldap", certainty=90, metadata=metadata)
            return None
        except (socket.timeout, OSError):
            return None
