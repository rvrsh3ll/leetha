"""IPMI probe plugin — RMCP ASF Ping to detect IPMI/BMC services."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IPMIProbePlugin(ServiceProbe):
    name = "ipmi"
    protocol = "udp"
    default_ports = [623]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build RMCP ASF Ping
            # RMCP header (4 bytes):
            #   version(1) + reserved(1) + sequence(1) + class(1)
            # ASF message (8 bytes):
            #   IANA enterprise(4) + message_type(1) + message_tag(1) +
            #   reserved(1) + data_length(1)
            rmcp_header = bytes([
                0x06,  # Version 1.0
                0x00,  # Reserved
                0xFF,  # Sequence number (0xFF = no ack)
                0x06,  # Message class: ASF
            ])

            asf_message = struct.pack(
                ">IBBBB",
                0x000011BE,  # IANA Enterprise Number (ASF)
                0x80,        # Message type: Presence Ping
                0x00,        # Message tag
                0x00,        # Reserved
                0x00,        # Data length
            )

            packet = rmcp_header + asf_message

            conn.write(packet)
            data = conn.read(1024)
            if not data or len(data) < 12:
                return None

            # Validate RMCP header
            if data[0] != 0x06:  # RMCP version
                return None
            if data[3] != 0x06:  # Message class: ASF
                return None

            # Parse ASF Pong response
            if len(data) < 12:
                return None

            iana_enterprise = struct.unpack_from(">I", data, 4)[0]
            message_type = data[8]

            # Check for ASF Pong (message type 0x40)
            if message_type != 0x40:
                return None

            metadata: dict = {
                "iana_enterprise": iana_enterprise,
            }

            # Parse ASF Pong data (if present)
            # data_length at byte 11
            data_length = data[11]
            if data_length >= 4 and len(data) >= 16:
                # IANA Enterprise for OEM (4 bytes)
                oem_iana = struct.unpack_from(">I", data, 12)[0]
                metadata["oem_iana"] = oem_iana

            if data_length >= 5 and len(data) >= 17:
                # OEM-defined byte
                metadata["oem_defined"] = data[16]

            if data_length >= 6 and len(data) >= 18:
                # Supported entities
                supported = data[17] if len(data) > 17 else 0
                metadata["ipmi_supported"] = bool(supported & 0x80)
                metadata["asf_v1_supported"] = bool(supported & 0x01)

            if data_length >= 7 and len(data) >= 19:
                # Supported interactions
                interactions = data[18] if len(data) > 18 else 0
                metadata["dash_supported"] = bool(interactions & 0x20)

            return ServiceIdentity(
                service="ipmi",
                certainty=85,
                version=None,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
