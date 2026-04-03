"""LLMNR probe plugin — Link-Local Multicast Name Resolution."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LLMNRProbePlugin(ServiceProbe):
    name = "llmnr"
    protocol = "udp"
    default_ports = [5355]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build LLMNR query (DNS format) for "leetha-probe"
            query_name = b"\x0aleetha-probe\x00"

            # LLMNR uses DNS message format
            transaction_id = b"\x00\x42"  # Arbitrary ID
            query = (
                transaction_id
                + b"\x00\x00"  # Flags: standard query (C bit = 0)
                + b"\x00\x01"  # Questions: 1
                + b"\x00\x00"  # Answers: 0
                + b"\x00\x00"  # Authority: 0
                + b"\x00\x00"  # Additional: 0
            )
            query += query_name
            query += b"\x00\x01"  # Type: A
            query += b"\x00\x01"  # Class: IN

            conn.write(query)
            data = conn.read(4096)

            if not data or len(data) < 12:
                return None

            # Check transaction ID matches
            if data[0:2] != transaction_id:
                return None

            # Check QR bit (response flag) set
            flags = struct.unpack(">H", data[2:4])[0]
            if not (flags & 0x8000):
                return None

            # LLMNR responses have the C bit (bit 10) = 0 for conflict,
            # and TC bit can vary. The key is QR=1 (response).
            ancount = struct.unpack(">H", data[6:8])[0]

            metadata: dict = {
                "flags": hex(flags),
                "answer_count": ancount,
            }

            # Check RCODE (bottom 4 bits of flags)
            rcode = flags & 0x000F
            metadata["rcode"] = rcode

            return ServiceIdentity(
                service="llmnr",
                certainty=75,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
