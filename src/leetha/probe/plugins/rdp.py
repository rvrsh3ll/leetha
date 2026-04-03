"""RDP probe plugin — Connection Request (X.224)."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RDPProbePlugin(ServiceProbe):
    name = "rdp"
    protocol = "tcp"
    default_ports = [3389]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # X.224 Connection Request
            cr = (
                b"\x03\x00"   # TPKT version 3
                b"\x00\x13"   # Length 19
                b"\x0e"       # X.224 length
                b"\xe0"       # Connection Request
                b"\x00\x00"   # DST-REF
                b"\x00\x00"   # SRC-REF
                b"\x00"       # Class 0
                b"\x01\x00\x08\x00\x03\x00\x00\x00"  # RDP negotiation request
            )
            conn.write(cr)
            data = conn.read(1024)
            if not data or len(data) < 11:
                return None
            # Check TPKT header
            if data[0] != 0x03:
                return None
            # Check for Connection Confirm (0xD0)
            if len(data) > 5 and data[5] == 0xD0:
                metadata = {"tpkt_version": data[1]}
                if len(data) > 19:
                    # Check negotiation response
                    metadata["negotiation"] = True
                return ServiceIdentity(service="rdp", certainty=90, metadata=metadata)
            return None
        except (socket.timeout, OSError, struct.error):
            return None
