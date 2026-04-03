"""HART-IP probe plugin — Session initiate request for device identification."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HARTIPProbePlugin(ServiceProbe):
    name = "hartip"
    protocol = "udp"
    default_ports = [5094]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # HART-IP Session Initiate Request
            # Version: 1
            # Message Type: 0 (Request)
            # Message ID: 0 (Session Initiate)
            # Status: 0
            # Sequence Number: 1
            # Byte Count: 5 (header only, no body beyond the header)
            request = struct.pack(
                ">BBBBHh",
                1,      # Version
                0,      # Message Type: Request
                0,      # Message ID: Session Initiate
                0,      # Status
                1,      # Sequence Number
                5,      # Byte Count (size of payload after header; minimal)
            )
            # Append an identity command body (command 0, byte count 0)
            request += struct.pack(">BH", 0, 0)  # Command 0 (Identity), Byte count 0

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Parse HART-IP response header
            version = data[0]
            msg_type = data[1]
            msg_id = data[2]
            status = data[3]

            # Validate HART-IP response
            if version < 1:
                return None

            # Message Type should be 1 (Response) or 2 (Publish)
            if msg_type not in (1, 2):
                # Some implementations echo with type 0 but valid structure
                if msg_type != 0:
                    return None

            metadata = {
                "version": version,
                "msg_type": msg_type,
                "msg_id": msg_id,
                "status": status,
            }

            if len(data) >= 6:
                seq_number = struct.unpack(">H", data[4:6])[0]
                metadata["sequence_number"] = seq_number

            if len(data) >= 8:
                byte_count = struct.unpack(">h", data[6:8])[0]
                metadata["byte_count"] = byte_count

            # Try to extract device info from payload
            if len(data) > 8:
                self._parse_payload(data[8:], metadata)

            return ServiceIdentity(
                service="hartip",
                certainty=80,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_payload(self, payload: bytes, metadata: dict) -> None:
        """Extract device information from HART-IP response payload."""
        try:
            if len(payload) >= 1:
                metadata["command"] = payload[0]
            if len(payload) >= 3:
                metadata["payload_byte_count"] = payload[1]
                metadata["response_code"] = payload[2]
            # If there is device-specific data, capture it
            if len(payload) > 3:
                device_data = payload[3:]
                # Try to extract readable strings
                text = device_data.decode("ascii", errors="replace")
                printable = "".join(c if c.isprintable() else "" for c in text)
                if len(printable) >= 3:
                    metadata["device_info"] = printable.strip()
        except (IndexError, struct.error):
            pass
