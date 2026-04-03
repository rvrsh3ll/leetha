"""S7comm (Siemens S7) probe plugin — COTP + S7 Communication Setup."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class S7commProbePlugin(ServiceProbe):
    name = "s7comm"
    protocol = "tcp"
    default_ports = [102]

    # COTP Connection Request (CR)
    COTP_CR = (
        b"\x03\x00\x00\x16"  # TPKT: version 3, reserved 0, length 22
        b"\x11\xe0"           # COTP CR: length 17, PDU type 0xE0
        b"\x00\x00"           # Destination reference
        b"\x00\x01"           # Source reference
        b"\x00"               # Class / option
        b"\xc0\x01\x0a"      # Parameter: TPDU size (1024)
        b"\xc1\x02\x01\x00"  # Parameter: src-tsap
        b"\xc2\x02\x01\x02"  # Parameter: dst-tsap
    )

    # S7 Communication Setup (wrapped in COTP Data + TPKT)
    S7_SETUP = (
        b"\x03\x00\x00\x19"  # TPKT header: length 25
        b"\x02\xf0\x80"      # COTP DT Data: length 2, PDU type 0xF0, TPDU# & EOT
        b"\x32"              # S7 protocol ID
        b"\x01"              # ROSCTR: Job (0x01)
        b"\x00\x00"          # Redundancy identification
        b"\x00\x00"          # Protocol data unit reference
        b"\x00\x08"          # Parameter length: 8
        b"\x00\x00"          # Data length: 0
        b"\xf0"              # Function: Setup communication (0xF0)
        b"\x00"              # Reserved
        b"\x00\x01"          # Max AmQ calling
        b"\x00\x01"          # Max AmQ called
        b"\x03\xc0"          # PDU length: 960
    )

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Step 1: Send COTP Connection Request
            conn.write(self.COTP_CR)
            data = conn.read(1024)
            if not data or len(data) < 7:
                return None

            # Check for TPKT header (version 3) and COTP CC (Connection Confirm = 0xD0)
            if data[0] != 0x03:
                return None
            # COTP PDU type is at byte 5 (after TPKT 4-byte header + COTP length byte)
            pdu_type = data[5] & 0xF0
            if pdu_type != 0xD0:
                return None

            metadata = {"cotp_confirmed": True}

            # Step 2: Send S7 Communication Setup
            conn.write(self.S7_SETUP)
            data = conn.read(1024)
            if not data or len(data) < 12:
                return ServiceIdentity(
                    service="s7comm",
                    certainty=75,
                    metadata=metadata,
                )

            # Parse S7 response
            # Look for S7 protocol ID (0x32) after TPKT (4 bytes) + COTP (3 bytes)
            s7_offset = self._find_s7_header(data)
            if s7_offset >= 0:
                metadata["s7_protocol"] = True
                self._parse_s7_response(data, s7_offset, metadata)

            version = metadata.get("module_type") or metadata.get("firmware")
            return ServiceIdentity(
                service="s7comm",
                certainty=90,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _find_s7_header(self, data: bytes) -> int:
        """Find offset of S7 protocol header (0x32) in response."""
        for i in range(4, len(data) - 2):
            if data[i] == 0x32:
                return i
        return -1

    def _parse_s7_response(self, data: bytes, offset: int, metadata: dict) -> None:
        """Parse S7 communication setup response for module/firmware info."""
        try:
            if offset + 12 > len(data):
                return
            rosctr = data[offset + 1]
            metadata["rosctr"] = rosctr
            param_len = struct.unpack(">H", data[offset + 6:offset + 8])[0]
            data_len = struct.unpack(">H", data[offset + 8:offset + 10])[0]
            metadata["param_length"] = param_len
            metadata["data_length"] = data_len

            # If there is data payload, try to extract text fields
            payload_offset = offset + 12 + param_len
            if data_len > 0 and payload_offset < len(data):
                payload = data[payload_offset:payload_offset + data_len]
                self._extract_strings(payload, metadata)
        except (IndexError, struct.error):
            pass

    def _extract_strings(self, payload: bytes, metadata: dict) -> None:
        """Extract readable ASCII strings from S7 data payload."""
        try:
            text = payload.decode("ascii", errors="replace")
            # Filter printable segments
            segments = []
            current = []
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
                metadata["module_type"] = segments[0]
            if len(segments) > 1:
                metadata["firmware"] = segments[1]
        except Exception:
            pass
