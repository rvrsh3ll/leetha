"""KNX/IP probe plugin — KNXnet/IP Search Request."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class KNXIPProbePlugin(ServiceProbe):
    name = "knxip"
    protocol = "udp"
    default_ports = [3671]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # KNXnet/IP Search Request
            # Header: header_length(1) + protocol_version(1) + service_type(2) + total_length(2)
            # HPAI (Host Protocol Address Information):
            #   structure_length(1) + host_protocol(1) + IP(4) + port(2)
            header_length = 0x06
            protocol_version = 0x10
            service_type = 0x0201  # SEARCH_REQUEST

            # HPAI: discovery endpoint
            hpai_length = 0x08
            hpai_protocol = 0x01  # IPV4_UDP
            # Use 0.0.0.0:0 to indicate "use source address"
            hpai_ip = b"\x00\x00\x00\x00"
            hpai_port = 0x0000

            hpai = struct.pack(
                ">BB4sH",
                hpai_length,
                hpai_protocol,
                hpai_ip,
                hpai_port,
            )

            total_length = header_length + len(hpai)
            header = struct.pack(
                ">BBHH",
                header_length,
                protocol_version,
                service_type,
                total_length,
            )

            request = header + hpai

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 6:
                return None

            # Parse KNXnet/IP response header
            resp_header_length = data[0]
            resp_protocol = data[1]
            resp_service_type = struct.unpack(">H", data[2:4])[0]
            resp_total_length = struct.unpack(">H", data[4:6])[0]

            # Check for valid KNX/IP header
            if resp_header_length != 0x06:
                return None
            if resp_protocol != 0x10:
                return None

            # Accept Search Response (0x0202) or Description Response (0x0204)
            if resp_service_type not in (0x0202, 0x0204):
                return None

            metadata = {
                "header_length": resp_header_length,
                "protocol_version": resp_protocol,
                "service_type": f"0x{resp_service_type:04X}",
                "total_length": resp_total_length,
            }

            # Parse device information from response
            if len(data) > 6:
                self._parse_search_response(data[6:], metadata)

            version = metadata.get("friendly_name")
            return ServiceIdentity(
                service="knxip",
                certainty=85,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_search_response(self, data: bytes, metadata: dict) -> None:
        """Parse KNXnet/IP Search Response body."""
        try:
            offset = 0

            # Skip HPAI control endpoint (8 bytes)
            if offset + 8 > len(data):
                return
            offset += 8

            # Device Information Block (DIB)
            # Structure length(1) + description type(1) + KNX medium(1) + ...
            if offset + 2 > len(data):
                return

            dib_length = data[offset]
            dib_type = data[offset + 1]

            if dib_type == 0x01 and dib_length >= 54:
                # Device Info DIB
                if offset + dib_length <= len(data):
                    dib = data[offset:offset + dib_length]
                    metadata["knx_medium"] = dib[2]

                    # Device status (byte 3)
                    metadata["device_status"] = dib[3]

                    # KNX individual address (bytes 4-5)
                    if len(dib) >= 6:
                        knx_addr = struct.unpack(">H", dib[4:6])[0]
                        area = (knx_addr >> 12) & 0x0F
                        line = (knx_addr >> 8) & 0x0F
                        device = knx_addr & 0xFF
                        metadata["knx_address"] = f"{area}.{line}.{device}"

                    # Serial number (bytes 8-13)
                    if len(dib) >= 14:
                        serial = dib[8:14].hex()
                        metadata["serial_number"] = serial

                    # Friendly name (bytes 24-53, null-terminated)
                    if len(dib) >= 54:
                        name = dib[24:54].decode(
                            "utf-8", errors="replace"
                        ).rstrip("\x00")
                        if name:
                            metadata["friendly_name"] = name
        except (IndexError, struct.error):
            pass
