"""SAP DIAG probe plugin — SAP GUI protocol detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SAPDiagProbePlugin(ServiceProbe):
    name = "sap_diag"
    protocol = "tcp"
    default_ports = [3200]

    # DIAG header markers
    _DIAG_INIT_MODE = 0x00
    _DIAG_DP_HEADER_LEN = 200

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a DIAG initialization request
            # NI header (4 bytes length) + DP header (200 bytes) + DIAG header
            dp_header = bytearray(self._DIAG_DP_HEADER_LEN)
            # DP header version at offset 17
            dp_header[17] = 0x00
            # Set action type to CYCLIC at offset 15
            dp_header[15] = 0x00

            # Minimal DIAG message header
            diag_header = bytearray(8)
            diag_header[0] = self._DIAG_INIT_MODE  # mode
            # Comm flag
            diag_header[1] = 0x00

            payload = bytes(dp_header) + bytes(diag_header)
            ni_header = struct.pack(">I", len(payload))

            conn.write(ni_header + payload)

            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            metadata: dict = {}

            # Check for NI header in response
            if len(data) >= 4:
                resp_len = struct.unpack(">I", data[0:4])[0]
                # SAP DIAG responses typically have reasonable lengths
                if resp_len < 4 or resp_len > 100000:
                    return None
                metadata["response_length"] = resp_len

            # Check for DP header in response (after NI header)
            if len(data) >= 4 + self._DIAG_DP_HEADER_LEN:
                # DP header found, this is likely a DIAG response
                metadata["dp_header"] = True
                return ServiceIdentity(
                    service="sap_diag",
                    certainty=80,
                    version=None,
                    metadata=metadata,
                )

            # Shorter response may be an error or rejection
            # Check for SAP-specific error patterns in response
            if len(data) >= 8:
                body = data[4:]
                # Look for DP header action type indicating DIAG protocol
                if len(body) >= 16 and body[15] in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05):
                    metadata["action_type"] = body[15]
                    return ServiceIdentity(
                        service="sap_diag",
                        certainty=65,
                        version=None,
                        metadata=metadata,
                    )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
