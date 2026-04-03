"""VTAM/SNA probe plugin — IBM mainframe SNA detection via TH/RH header probe."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class VTAMProbePlugin(ServiceProbe):
    name = "vtam"
    protocol = "tcp"
    default_ports = [1090]

    # SNA Transmission Header marker byte
    _SNA_TH_MARKER = 0x2C

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal SNA TH (Transmission Header) probe
            # TH format: FID type (first nibble) + other fields
            # FID2 TH is 6 bytes: 0x2C prefix, DAF, OAF, sequence
            th_header = bytes([
                self._SNA_TH_MARKER, 0x00,  # TH byte 0-1: FID2 indicator
                0x00, 0x01,                   # DAF/OAF
                0x00, 0x01,                   # Sequence number
            ])
            # RH (Request/Response Header) - 3 bytes
            rh_header = bytes([0x00, 0x00, 0x00])

            packet = th_header + rh_header
            conn.write(packet)

            data = conn.read(4096)
            if not data or len(data) < 6:
                return None

            # Look for SNA TH response pattern
            metadata: dict = {}
            found_sna = False

            # Check if response starts with SNA TH marker
            if data[0] == self._SNA_TH_MARKER:
                found_sna = True
                metadata["fid_type"] = (data[0] >> 4) & 0x0F
                if len(data) >= 6:
                    metadata["daf"] = data[2]
                    metadata["oaf"] = data[3]
                    metadata["seq"] = struct.unpack(">H", data[4:6])[0]

            # Also check for SNA TH marker anywhere in first 32 bytes
            if not found_sna:
                for offset in range(min(len(data), 32)):
                    if data[offset] == self._SNA_TH_MARKER:
                        # Verify it looks like a valid TH
                        if offset + 6 <= len(data):
                            found_sna = True
                            metadata["th_offset"] = offset
                            break

            if not found_sna:
                return None

            return ServiceIdentity(
                service="vtam",
                certainty=75,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
