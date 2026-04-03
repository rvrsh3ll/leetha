"""Milter probe plugin — mail filter protocol (SMFIC_OPTNEG)."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MilterProbePlugin(ServiceProbe):
    name = "milter"
    protocol = "tcp"
    default_ports = [8891, 8893]

    # Milter SMFIC_OPTNEG command byte
    _SMFIC_OPTNEG = ord("O")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send SMFIC_OPTNEG: 4-byte length + 'O' + version(uint32) + actions(uint32) + protocol(uint32)
            # Version 6, no actions, no protocol flags
            payload = struct.pack(">cIII", b"O", 6, 0, 0)
            length = struct.pack(">I", len(payload))
            conn.write(length + payload)

            # Read response: 4-byte length
            hdr = b""
            while len(hdr) < 4:
                chunk = conn.read(4 - len(hdr))
                if not chunk:
                    return None
                hdr += chunk

            resp_len = struct.unpack(">I", hdr)[0]
            if resp_len < 1 or resp_len > 65536:
                return None

            # Read the response payload
            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = conn.read(resp_len - len(resp_data))
                if not chunk:
                    return None
                resp_data += chunk

            # First byte should be 'O' (SMFIC_OPTNEG response)
            if resp_data[0] != self._SMFIC_OPTNEG:
                return None

            # Parse version, actions, protocol from response
            if len(resp_data) < 13:
                return None

            ver, actions, proto = struct.unpack(">III", resp_data[1:13])

            metadata: dict = {
                "milter_version": ver,
                "actions": actions,
                "protocol": proto,
            }

            return ServiceIdentity(
                service="milter",
                certainty=85,
                version=str(ver),
                metadata=metadata,
                banner=None,
            )
        except (socket.timeout, OSError):
            return None
