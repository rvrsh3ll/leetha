"""Codesys V3 probe plugin — Proprietary binary protocol identification."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CodesysProbePlugin(ServiceProbe):
    name = "codesys"
    protocol = "tcp"
    default_ports = [1217, 11740]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Codesys V3 uses a proprietary Layer 7 protocol
            # Initial handshake: send a block driver request
            # The protocol starts with a magic header
            # Block driver header:
            #   Magic: 0xBBBB (little-endian)
            #   Block length: 0x0000 (to be filled)
            #   Block type: 0x01 (request)
            #   Service group: 0x01 (device info)
            #   Service: 0x01 (get info)
            #   Session ID: 0x00000000
            #   Message ID: 0x00000001

            magic = struct.pack("<H", 0xBBBB)
            header_len = 16  # total header size
            block_type = struct.pack("<B", 0x01)      # Request
            padding = struct.pack("<B", 0x00)
            service_group = struct.pack("<H", 0x0001)  # Device info
            service = struct.pack("<H", 0x0001)        # Get info
            session_id = struct.pack("<I", 0x00000000)
            reserved = struct.pack("<H", 0x0000)

            body = block_type + padding + service_group + service + session_id + reserved
            block_length = struct.pack("<H", len(body))

            request = magic + block_length + body

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 4:
                return None

            metadata = {}

            # Check for Codesys magic header in response
            resp_magic = struct.unpack("<H", data[0:2])[0]
            if resp_magic != 0xBBBB:
                return None

            metadata["magic"] = f"0x{resp_magic:04X}"

            if len(data) >= 4:
                resp_block_length = struct.unpack("<H", data[2:4])[0]
                metadata["block_length"] = resp_block_length

            if len(data) >= 5:
                resp_block_type = data[4]
                metadata["block_type"] = resp_block_type

            if len(data) >= 8:
                resp_service_group = struct.unpack("<H", data[6:8])[0]
                metadata["service_group"] = resp_service_group

            if len(data) >= 10:
                resp_service = struct.unpack("<H", data[8:10])[0]
                metadata["service"] = resp_service

            # Try to extract device info from payload
            if len(data) > 16:
                self._parse_device_info(data[16:], metadata)

            version = metadata.get("device_name")
            return ServiceIdentity(
                service="codesys",
                certainty=75,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_device_info(self, payload: bytes, metadata: dict) -> None:
        """Try to extract device name or version from Codesys response payload."""
        try:
            # Look for null-terminated ASCII strings in the payload
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
                metadata["device_name"] = segments[0]
            if len(segments) > 1:
                metadata["device_version"] = segments[1]
        except (IndexError, struct.error):
            pass
