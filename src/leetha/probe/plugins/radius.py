"""RADIUS probe plugin — Remote Authentication Dial-In User Service."""
from __future__ import annotations
import os
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RADIUSProbePlugin(ServiceProbe):
    name = "radius"
    protocol = "udp"
    default_ports = [1812, 1813]

    # RADIUS response codes
    RESPONSE_CODES = {
        2: "Access-Accept",
        3: "Access-Reject",
        5: "Accounting-Response",
        11: "Access-Challenge",
    }

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build RADIUS Access-Request
            code = 1  # Access-Request
            identifier = 0x01
            authenticator = os.urandom(16)

            # Add User-Name attribute (type 1): "test"
            username = b"test"
            attr_user = struct.pack("BB", 1, 2 + len(username)) + username

            # Total length = 20 (header) + attributes
            total_length = 20 + len(attr_user)

            packet = struct.pack(
                ">BBH", code, identifier, total_length
            ) + authenticator + attr_user

            conn.write(packet)
            data = conn.read(4096)

            if not data or len(data) < 20:
                return None

            # Parse RADIUS response header
            resp_code, resp_id, resp_length = struct.unpack(">BBH", data[0:4])

            # Valid RADIUS response codes
            if resp_code not in self.RESPONSE_CODES:
                return None

            metadata: dict = {
                "response_code": resp_code,
                "response_type": self.RESPONSE_CODES.get(resp_code, "unknown"),
            }

            return ServiceIdentity(
                service="radius",
                certainty=80,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
