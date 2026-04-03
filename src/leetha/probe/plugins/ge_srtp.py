"""GE SRTP (Service Request Transport Protocol) probe plugin."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GESRTPProbePlugin(ServiceProbe):
    name = "ge_srtp"
    protocol = "tcp"
    default_ports = [18245]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # GE SRTP Init Request
            # The SRTP protocol uses a 56-byte header
            # Type: 0x00 (init request)
            # Followed by padding/reserved fields
            request = bytearray(56)
            request[0] = 0x02   # Version
            request[1] = 0x00   # Type: init
            # Sequence number (bytes 2-3)
            struct.pack_into(">H", request, 2, 0x0001)
            # Data length (bytes 4-5), 0 for init
            struct.pack_into(">H", request, 4, 0x0000)
            # Text length (bytes 6-7)
            struct.pack_into(">H", request, 6, 0x0000)
            # Service request type (byte 8)
            request[8] = 0x00  # Init
            # Mailbox source (bytes 30-31)
            struct.pack_into(">H", request, 30, 0x0001)
            # Mailbox destination (bytes 32-33)
            struct.pack_into(">H", request, 32, 0x0001)

            conn.write(bytes(request))
            data = conn.read(4096)
            if not data or len(data) < 10:
                return None

            metadata = {}

            # Validate SRTP response
            # Check version byte
            resp_version = data[0]
            if resp_version not in (0x01, 0x02, 0x03):
                return None

            metadata["version"] = resp_version
            metadata["type"] = data[1]

            if len(data) >= 4:
                seq_number = struct.unpack(">H", data[2:4])[0]
                metadata["sequence_number"] = seq_number

            if len(data) >= 6:
                data_length = struct.unpack(">H", data[4:6])[0]
                metadata["data_length"] = data_length

            if len(data) >= 9:
                service_request_type = data[8]
                metadata["service_request_type"] = service_request_type

            # Try to extract PLC info from response
            if len(data) > 56:
                self._parse_plc_info(data[56:], metadata)

            return ServiceIdentity(
                service="ge_srtp",
                certainty=80,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_plc_info(self, payload: bytes, metadata: dict) -> None:
        """Extract PLC information from SRTP response payload."""
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
                metadata["plc_model"] = segments[0]
        except (IndexError, struct.error):
            pass
