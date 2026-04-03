"""IEC 61850 MMS probe plugin — COTP + MMS Initiate handshake.

Shares conn.port 102 with S7comm. Distinguished by sending MMS transport selectors
in the COTP CR, then an MMS Initiate-Request. Returns None if only COTP is
confirmed (ambiguous with S7) — requires MMS-level confirmation.
"""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IEC61850ProbePlugin(ServiceProbe):
    name = "iec61850"
    protocol = "tcp"
    default_ports = [102]

    # COTP Connection Request (CR) with MMS transport selectors
    # src-tsap=0x0001, dst-tsap=0x0001 (MMS convention)
    COTP_CR = (
        b"\x03\x00\x00\x16"  # TPKT: version 3, reserved 0, length 22
        b"\x11\xe0"           # COTP CR: length 17, PDU type 0xE0
        b"\x00\x00"           # Destination reference
        b"\x00\x01"           # Source reference
        b"\x00"               # Class / option
        b"\xc0\x01\x0a"      # Parameter: TPDU size (1024)
        b"\xc1\x02\x00\x01"  # Parameter: src-tsap = 0x0001
        b"\xc2\x02\x00\x01"  # Parameter: dst-tsap = 0x0001
    )

    # MMS Initiate-Request wrapped in TPKT + COTP DT
    # ASN.1 BER: tag 0xA8 (context-constructed 8 = Initiate-Request)
    _MMS_INITIATE_REQUEST = (
        b"\xa8\x26"              # Initiate-RequestPDU, length 38
        b"\x80\x03\x00\xfd\xe8" # localDetailCalling = 65000
        b"\x81\x01\x05"         # proposedMaxServOutstandingCalling = 5
        b"\x82\x01\x05"         # proposedMaxServOutstandingCalled = 5
        b"\x83\x01\x0a"         # proposedDataStructureNestingLevel = 10
        b"\xa4\x16"             # initRequestDetail (constructed)
        b"\x80\x01\x01"         # proposedVersionNumber = 1
        b"\x81\x03\x05\xf1\x00"  # proposedParameterCBB (bitstring)
        b"\x82\x0c\x03\xee\x1c\x00\x00\x04\x08\x00\x00\x79\xef\x18"
                                 # servicesSupportedCalling (bitstring)
    )

    MMS_INITIATE = (
        b"\x03\x00\x00\x2f"  # TPKT: version 3, length 47
        b"\x02\xf0\x80"      # COTP DT Data
    ) + _MMS_INITIATE_REQUEST

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Step 1: Send COTP Connection Request
            conn.write(self.COTP_CR)
            data = conn.read(1024)
            if not data or len(data) < 7:
                return None

            # Check for TPKT header (version 3) and COTP CC (0xD0)
            if data[0] != 0x03:
                return None
            pdu_type = data[5] & 0xF0
            if pdu_type != 0xD0:
                return None

            # COTP confirmed, but not sufficient alone (ambiguous with S7)
            metadata: dict = {"cotp_confirmed": True}

            # Step 2: Send MMS Initiate-Request
            conn.write(self.MMS_INITIATE)
            data = conn.read(4096)
            if not data or len(data) < 9:
                return None

            # Expect TPKT + COTP DT + MMS PDU
            if data[0] != 0x03:
                return None

            # Find MMS PDU after TPKT (4 bytes) + COTP DT (3 bytes)
            mms_offset = 7
            if mms_offset >= len(data):
                return None

            mms_tag = data[mms_offset]

            # 0xA9 = Initiate-ResponsePDU (context-constructed 9)
            if mms_tag == 0xA9:
                metadata["mms_initiate_response"] = True
                self._parse_initiate_response(data, mms_offset, metadata)
                version = metadata.get("vendor") or metadata.get("model")
                return ServiceIdentity(
                    service="iec61850",
                    certainty=90,
                    version=version,
                    metadata=metadata,
                )

            # Other MMS PDU tags (confirmed-request 0xA0, confirmed-response 0xA1,
            # confirmed-error 0xA2, reject 0xA4, etc.) — still MMS but less certain
            if mms_tag & 0xE0 == 0xA0:
                metadata["mms_pdu_tag"] = hex(mms_tag)
                return ServiceIdentity(
                    service="iec61850",
                    certainty=85,
                    metadata=metadata,
                )

            # No MMS confirmation — return None (could be S7 or something else)
            return None

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_initiate_response(
        self, data: bytes, offset: int, metadata: dict
    ) -> None:
        """Try to extract version/vendor/model from MMS Initiate-Response."""
        try:
            # Skip tag byte; parse BER length
            pos = offset + 1
            length, pos = self._ber_length(data, pos)
            end = pos + length
            if end > len(data):
                end = len(data)

            while pos < end - 2:
                tag = data[pos]
                pos += 1
                field_len, pos = self._ber_length(data, pos)
                field_end = pos + field_len

                if tag == 0x80:  # localDetailCalled (integer)
                    metadata["local_detail"] = int.from_bytes(
                        data[pos:field_end], "big"
                    )
                elif tag == 0xA4:  # initResponseDetail (constructed)
                    self._parse_init_response_detail(
                        data, pos, field_end, metadata
                    )

                pos = field_end

        except (IndexError, ValueError):
            pass

    def _parse_init_response_detail(
        self, data: bytes, start: int, end: int, metadata: dict
    ) -> None:
        """Parse initResponseDetail for version and vendor info."""
        try:
            pos = start
            while pos < end - 2:
                tag = data[pos]
                pos += 1
                field_len, pos = self._ber_length(data, pos)
                field_end = pos + field_len

                if tag == 0x80:  # negotiatedVersionNumber
                    metadata["mms_version"] = int.from_bytes(
                        data[pos:field_end], "big"
                    )

                pos = field_end

            # Extract readable ASCII strings (vendor, model) from payload
            self._extract_strings(data[start:end], metadata)
        except (IndexError, ValueError):
            pass

    def _extract_strings(self, payload: bytes, metadata: dict) -> None:
        """Extract readable ASCII strings from MMS response payload."""
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
                metadata["vendor"] = segments[0]
            if len(segments) > 1:
                metadata["model"] = segments[1]
        except Exception:
            pass

    @staticmethod
    def _ber_length(data: bytes, pos: int) -> tuple[int, int]:
        """Parse BER length field; return (length, new_pos)."""
        b = data[pos]
        if b < 0x80:
            return b, pos + 1
        num_bytes = b & 0x7F
        length = int.from_bytes(data[pos + 1: pos + 1 + num_bytes], "big")
        return length, pos + 1 + num_bytes
