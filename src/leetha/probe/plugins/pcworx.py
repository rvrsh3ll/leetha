"""Phoenix Contact PCWorx probe plugin — Proprietary init request."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PCWorxProbePlugin(ServiceProbe):
    name = "pcworx"
    protocol = "tcp"
    default_ports = [1962]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # PCWorx init request
            # The protocol uses a proprietary binary format
            # Header: length (2 bytes, big-endian) + type (1 byte) + sub-type (1 byte)
            # Init request type: 0x01, sub-type: 0x01
            body = bytes([
                0x01, 0x01,       # Type: Init Request
                0x00, 0x02,       # Protocol version
                0x00, 0x00,       # Flags
                0x00, 0x00,       # Session ID
                0x00, 0x00, 0x00, 0x00,  # Reserved
            ])
            length = struct.pack(">H", len(body))
            request = length + body

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 4:
                return None

            metadata = {}

            # Parse response length
            resp_length = struct.unpack(">H", data[0:2])[0]
            metadata["response_length"] = resp_length

            if len(data) >= 4:
                resp_type = data[2]
                resp_subtype = data[3]
                metadata["type"] = resp_type
                metadata["subtype"] = resp_subtype

                # Valid PCWorx response should have a recognizable type
                # Type 0x01 or 0x81 for init response
                if resp_type not in (0x01, 0x02, 0x81, 0x82):
                    return None

            if len(data) >= 6:
                proto_version = struct.unpack(">H", data[4:6])[0]
                metadata["protocol_version"] = proto_version

            # Try to extract device info
            if len(data) > 14:
                self._parse_device_info(data[14:], metadata)

            return ServiceIdentity(
                service="pcworx",
                certainty=75,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_device_info(self, payload: bytes, metadata: dict) -> None:
        """Extract device information from PCWorx response payload."""
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
                metadata["device_model"] = segments[0]
            if len(segments) > 1:
                metadata["firmware_version"] = segments[1]
        except (IndexError, struct.error):
            pass
