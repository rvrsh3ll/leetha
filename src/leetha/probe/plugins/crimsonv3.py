"""Red Lion Crimson V3 probe plugin — Protocol discovery request."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CrimsonV3ProbePlugin(ServiceProbe):
    name = "crimsonv3"
    protocol = "tcp"
    default_ports = [789]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Crimson V3 discovery request
            # The protocol uses a simple binary format
            # Header: sync(2) + length(2) + command(2) + sequence(2)
            # Sync: 0x00 0x00
            # Command: 0x0001 (Get Device Info)
            sync = struct.pack(">H", 0x0000)
            command = struct.pack(">H", 0x0001)  # Get device info
            sequence = struct.pack(">H", 0x0001)
            body = b""
            length = struct.pack(">H", 8 + len(body))  # Total packet length

            request = sync + length + command + sequence + body

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 4:
                return None

            metadata = {}

            # Parse response header
            resp_sync = struct.unpack(">H", data[0:2])[0]
            metadata["sync"] = resp_sync

            if len(data) >= 4:
                resp_length = struct.unpack(">H", data[2:4])[0]
                metadata["response_length"] = resp_length

            if len(data) >= 6:
                resp_command = struct.unpack(">H", data[4:6])[0]
                metadata["command"] = resp_command

            if len(data) >= 8:
                resp_sequence = struct.unpack(">H", data[6:8])[0]
                metadata["sequence"] = resp_sequence

            # Try to extract device info from payload
            if len(data) > 8:
                self._parse_device_info(data[8:], metadata)

            return ServiceIdentity(
                service="crimsonv3",
                certainty=70,
                version=metadata.get("model"),
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_device_info(self, payload: bytes, metadata: dict) -> None:
        """Extract device information from Crimson V3 response."""
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
                metadata["model"] = segments[0]
            if len(segments) > 1:
                metadata["firmware"] = segments[1]
        except (IndexError, struct.error):
            pass
