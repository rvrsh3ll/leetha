"""ProConOS (Wago) probe plugin — Information request."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ProConOSProbePlugin(ServiceProbe):
    name = "proconos"
    protocol = "tcp"
    default_ports = [20547]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # ProConOS uses a proprietary binary protocol
            # Information request packet:
            # Header: sync(1) + length(2) + counter(1) + type(1)
            # Sync byte: 0xCC
            # Type: 0x96 (Get PLC Info)
            counter = 0x01
            msg_type = 0x96  # Get PLC Info
            body = bytes([])  # Empty body for info request
            length = struct.pack("<H", len(body) + 2)  # +2 for counter + type

            request = bytes([0xCC]) + length + bytes([counter, msg_type]) + body

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 5:
                return None

            # Validate ProConOS response
            # Check sync byte
            if data[0] != 0xCC:
                return None

            metadata = {}

            resp_length = struct.unpack("<H", data[1:3])[0]
            metadata["response_length"] = resp_length

            if len(data) >= 4:
                resp_counter = data[3]
                metadata["counter"] = resp_counter

            if len(data) >= 5:
                resp_type = data[4]
                metadata["type"] = resp_type

            # Parse system info from response payload
            if len(data) > 5:
                self._parse_system_info(data[5:], metadata)

            return ServiceIdentity(
                service="proconos",
                certainty=75,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_system_info(self, payload: bytes, metadata: dict) -> None:
        """Extract system information from ProConOS response."""
        try:
            text = payload.decode("ascii", errors="replace")
            segments = []
            current: list[str] = []
            for ch in text:
                if ch.isprintable() and ch != "\ufffd":
                    current.append(ch)
                else:
                    if len(current) >= 3:
                        segments.append("".join(current))
                    current = []
            if len(current) >= 3:
                segments.append("".join(current))
            if segments:
                metadata["system_name"] = segments[0]
            if len(segments) > 1:
                metadata["system_version"] = segments[1]
        except (IndexError, struct.error):
            pass
