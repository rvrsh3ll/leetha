"""RTMP probe plugin — Real-Time Messaging Protocol handshake."""
from __future__ import annotations

import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RTMPProbePlugin(ServiceProbe):
    name = "rtmp"
    protocol = "tcp"
    default_ports = [1935]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # C0 (version byte 0x03) + C1 (1536 bytes: 4-byte time + 4-byte zero + 1528 random)
            c0 = b"\x03"
            c1 = b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 1528
            conn.write(c0 + c1)

            # Expect S0 (1 byte) + S1 (1536 bytes) = 1537 bytes minimum
            data = b""
            while len(data) < 1537:
                chunk = conn.read(4096)
                if not chunk:
                    break
                data += chunk

            if len(data) < 1537:
                return None

            # S0 must be version 0x03
            s0 = data[0]
            if s0 != 0x03:
                return None

            metadata: dict = {"s0_version": s0}
            return ServiceIdentity(
                service="rtmp",
                certainty=85,
                version=None,
                metadata=metadata,
                banner=None,
            )
        except (socket.timeout, OSError):
            return None
