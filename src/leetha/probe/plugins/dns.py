"""DNS probe plugin — version.bind query."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DNSProbePlugin(ServiceProbe):
    name = "dns"
    protocol = "udp"
    default_ports = [53]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Query: version.bind TXT CH
            query = (
                b"\xaa\xbb"  # Transaction ID
                b"\x00\x00"  # Standard query
                b"\x00\x01"  # Questions: 1
                b"\x00\x00\x00\x00\x00\x00"  # Answers/Auth/Additional: 0
                b"\x07version\x04bind\x00"  # version.bind
                b"\x00\x10"  # Type: TXT
                b"\x00\x03"  # Class: CH (Chaos)
            )
            conn.write(query)
            data = conn.read(1024)
            if not data or len(data) < 12:
                return None
            # Check it's a DNS response (QR bit set)
            flags = struct.unpack(">H", data[2:4])[0]
            if not (flags & 0x8000):
                return None
            metadata = {}
            # Try to extract TXT answer
            ancount = struct.unpack(">H", data[6:8])[0]
            if ancount > 0:
                # Rough TXT extraction
                txt_data = data[12:]
                txt_str = txt_data.decode("utf-8", errors="replace")
                metadata["raw_response"] = txt_str[:200]
            return ServiceIdentity(service="dns", certainty=85, metadata=metadata)
        except (socket.timeout, OSError, struct.error):
            return None
