"""DDS/RTPS probe plugin — OMG Data Distribution Service discovery."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DDSProbePlugin(ServiceProbe):
    name = "dds"
    protocol = "udp"
    default_ports = [7400]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build RTPS discovery message
            # Magic: "RTPS"
            # Protocol version: 2.4
            # Vendor ID: 0x0000 (unknown)
            # GUID prefix: 12 bytes
            header = b"RTPS"
            header += struct.pack("BB", 2, 4)       # protocol version 2.4
            header += struct.pack("!H", 0x0000)      # vendor id
            header += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"  # GUID prefix

            # Submessage: INFO_TS (0x09), flags=0x01 (little-endian), length=8
            submsg = struct.pack("<BBH", 0x09, 0x01, 8)
            submsg += struct.pack("<II", 0, 0)  # timestamp

            packet = header + submsg
            conn.write(packet)
            data = conn.read(4096)

            if not data or len(data) < 20:
                return None

            # Check for RTPS magic
            if data[:4] != b"RTPS":
                return None

            # Parse protocol version
            proto_major = data[4]
            proto_minor = data[5]

            # Parse vendor ID
            vendor_id = struct.unpack("!H", data[6:8])[0]

            metadata: dict = {
                "protocol_version": f"{proto_major}.{proto_minor}",
                "vendor_id": vendor_id,
            }

            # Extract GUID prefix
            guid_prefix = data[8:20]
            metadata["guid_prefix"] = guid_prefix.hex()

            version = f"{proto_major}.{proto_minor}"

            return ServiceIdentity(
                service="dds",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
