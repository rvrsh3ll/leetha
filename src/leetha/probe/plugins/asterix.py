"""ASTERIX (All Purpose Structured Eurocontrol Surveillance Information Exchange) probe plugin."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ASTERIXProbePlugin(ServiceProbe):
    name = "asterix"
    protocol = "udp"
    default_ports = [8600]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send a minimal ASTERIX category 1 query (surveillance data)
            # ASTERIX data block: CAT(1 byte) + LEN(2 bytes, big-endian)
            # Category 34 = System Configuration and Monitoring Data
            cat = 34
            # Minimal record: just the header (length includes the 3-byte header)
            length = 3
            query = struct.pack(">BH", cat, length)
            conn.write(query)

            data = conn.read(4096)
            if not data or len(data) < 3:
                return None

            # Parse ASTERIX data block header
            resp_cat = data[0]
            resp_len = struct.unpack(">H", data[1:3])[0]

            # Validate: length must be at least 3 and not exceed data size
            if resp_len < 3 or resp_len > len(data):
                return None

            # Valid ASTERIX categories: 1-255 (0 is reserved)
            if resp_cat == 0:
                return None

            metadata: dict = {
                "category": resp_cat,
                "block_length": resp_len,
            }

            return ServiceIdentity(
                service="asterix",
                certainty=80,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
