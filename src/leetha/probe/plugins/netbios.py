"""NetBIOS probe plugin — NetBIOS Name Service wildcard query."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NetBIOSProbePlugin(ServiceProbe):
    name = "netbios"
    protocol = "udp"
    default_ports = [137]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build NetBIOS Name Query for "*" (wildcard)
            # Encode "*" in NetBIOS first-level encoding:
            # Each char -> two bytes: ((ch >> 4) + ord('A')), ((ch & 0x0F) + ord('A'))
            # "*" = 0x2A -> 'C', 'K' then pad with 15 null chars (each -> 'A', 'A')
            encoded_name = b"\x20"  # length 32
            # '*' encoded
            encoded_name += bytes([ord("C"), ord("K")])
            # 15 null pad chars -> 'AA' each
            encoded_name += b"AA" * 15
            encoded_name += b"\x00"  # terminator

            query = (
                b"\x00\x01"  # Transaction ID
                b"\x00\x00"  # Flags: standard query
                b"\x00\x01"  # QDCount: 1
                b"\x00\x00"  # ANCount: 0
                b"\x00\x00"  # NSCount: 0
                b"\x00\x00"  # ARCount: 0
            )
            query += encoded_name
            query += b"\x00\x21"  # Type: NBSTAT (0x0021)
            query += b"\x00\x01"  # Class: IN

            conn.write(query)
            data = conn.read(4096)

            if not data or len(data) < 12:
                return None

            # Check transaction ID matches
            if data[0:2] != b"\x00\x01":
                return None

            # Check QR bit (response flag) in flags
            flags = struct.unpack(">H", data[2:4])[0]
            if not (flags & 0x8000):
                return None

            ancount = struct.unpack(">H", data[6:8])[0]

            metadata: dict = {"answer_count": ancount}
            names: list[dict] = []
            banner = None

            # Try to parse NBSTAT response
            if ancount > 0 and len(data) > 56:
                # Skip question section (variable length), find answer data
                # After header (12 bytes), skip the name + type + class in answer
                offset = 12
                # Skip answer name (could be compressed pointer or full name)
                if offset < len(data):
                    if data[offset] & 0xC0 == 0xC0:
                        offset += 2  # compressed pointer
                    else:
                        # Skip full name
                        while offset < len(data) and data[offset] != 0:
                            offset += data[offset] + 1
                        offset += 1  # null terminator
                # Skip type(2) + class(2) + TTL(4) + rdlength(2)
                offset += 10
                if offset < len(data):
                    num_names = data[offset]
                    offset += 1
                    for _ in range(min(num_names, 20)):
                        if offset + 18 > len(data):
                            break
                        nb_name = data[offset:offset + 15].rstrip(b"\x20\x00").decode(
                            "ascii", errors="replace"
                        )
                        suffix = data[offset + 15]
                        flags_word = struct.unpack(">H", data[offset + 16:offset + 18])[0]
                        group = bool(flags_word & 0x8000)
                        names.append({
                            "name": nb_name,
                            "suffix": hex(suffix),
                            "group": group,
                        })
                        offset += 18

            if names:
                metadata["names"] = names
                banner = ", ".join(n["name"] for n in names[:5])

            return ServiceIdentity(
                service="netbios",
                certainty=80,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
