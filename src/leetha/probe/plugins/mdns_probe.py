"""mDNS probe plugin — multicast DNS service discovery query."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MDNSProbePlugin(ServiceProbe):
    name = "mdns_probe"
    protocol = "udp"
    default_ports = [5353]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build mDNS query for _services._dns-sd._udp.local
            # DNS header
            query = (
                b"\x00\x00"  # Transaction ID (mDNS uses 0)
                b"\x00\x00"  # Flags: standard query
                b"\x00\x01"  # Questions: 1
                b"\x00\x00"  # Answers: 0
                b"\x00\x00"  # Authority: 0
                b"\x00\x00"  # Additional: 0
            )
            # QNAME: _services._dns-sd._udp.local
            query += (
                b"\x09_services"
                b"\x07_dns-sd"
                b"\x04_udp"
                b"\x05local"
                b"\x00"
            )
            query += b"\x00\x0c"  # QTYPE: PTR (12)
            query += b"\x00\x01"  # QCLASS: IN

            conn.write(query)
            data = conn.read(4096)

            if not data or len(data) < 12:
                return None

            # Check QR bit (response flag)
            flags = struct.unpack(">H", data[2:4])[0]
            if not (flags & 0x8000):
                return None

            ancount = struct.unpack(">H", data[6:8])[0]
            metadata: dict = {"answer_count": ancount}
            services: list[str] = []

            # Try to extract PTR record names from answers
            if ancount > 0:
                offset = 12
                # Skip question section
                qdcount = struct.unpack(">H", data[4:6])[0]
                for _ in range(qdcount):
                    while offset < len(data) and data[offset] != 0:
                        if data[offset] & 0xC0 == 0xC0:
                            offset += 2
                            break
                        offset += data[offset] + 1
                    else:
                        offset += 1  # null terminator
                    offset += 4  # QTYPE + QCLASS

                # Parse answer records
                for _ in range(min(ancount, 10)):
                    if offset >= len(data):
                        break
                    # Skip answer name
                    if data[offset] & 0xC0 == 0xC0:
                        offset += 2
                    else:
                        while offset < len(data) and data[offset] != 0:
                            offset += data[offset] + 1
                        offset += 1

                    if offset + 10 > len(data):
                        break
                    rtype = struct.unpack(">H", data[offset:offset + 2])[0]
                    rdlength = struct.unpack(">H", data[offset + 8:offset + 10])[0]
                    offset += 10

                    if rtype == 12:  # PTR record
                        # Try to decode the domain name in RDATA
                        ptr_name = self._decode_dns_name(data, offset)
                        if ptr_name:
                            services.append(ptr_name)

                    offset += rdlength

            if services:
                metadata["services"] = services

            return ServiceIdentity(
                service="mdns",
                certainty=78,
                metadata=metadata,
                banner=", ".join(services[:5]) if services else None,
            )
        except (socket.timeout, OSError, struct.error):
            return None

    @staticmethod
    def _decode_dns_name(data: bytes, offset: int) -> str | None:
        """Decode a DNS domain name from packet data."""
        parts: list[str] = []
        seen_offsets: set[int] = set()
        while offset < len(data):
            if offset in seen_offsets:
                break
            seen_offsets.add(offset)
            length = data[offset]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:
                # Compressed pointer
                if offset + 1 >= len(data):
                    break
                ptr = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
                offset = ptr
                continue
            offset += 1
            if offset + length > len(data):
                break
            parts.append(data[offset:offset + length].decode("utf-8", errors="replace"))
            offset += length
        return ".".join(parts) if parts else None
