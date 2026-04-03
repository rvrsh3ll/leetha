"""L2TP probe plugin — sends SCCRQ (Start-Control-Connection-Request)."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class L2TPProbePlugin(ServiceProbe):
    name = "l2tp"
    protocol = "udp"
    default_ports = [1701]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build L2TP SCCRQ (Start-Control-Connection-Request)
            # L2TP header flags:
            #   T=1 (control), L=1 (length present), S=1 (sequence numbers)
            #   = 0xC802
            flags_ver = 0xC802
            tunnel_id = 0  # Not yet assigned
            session_id = 0  # Not yet assigned
            ns = 0  # Sequence number (send)
            nr = 0  # Sequence number (receive)

            # AVP: Message Type = SCCRQ (1)
            avp_msg_type = struct.pack(">HHH",
                                       0x8008,  # M bit set, length 8 (6 header + 2 value)
                                       0x0000,  # Vendor ID: IETF
                                       0x0000,  # Attribute Type: Message Type
                                       ) + struct.pack(">H", 1)  # SCCRQ

            # AVP: Protocol Version (1.0)
            avp_proto_ver = struct.pack(">HHH",
                                        0x8008,  # M bit set, length 8 (6 header + 2 value)
                                        0x0000,  # Vendor ID: IETF
                                        0x0002,  # Attribute Type: Protocol Version
                                        ) + struct.pack(">BB", 1, 0)  # v1.0

            # AVP: Framing Capabilities
            avp_framing = struct.pack(">HHH",
                                      0x800A,  # M bit set, length 10 (6 header + 4 value)
                                      0x0000,  # Vendor ID: IETF
                                      0x0003,  # Attribute Type: Framing Capabilities
                                      ) + struct.pack(">I", 3)  # Sync + Async

            # AVP: Host Name
            hostname = b"leetha"
            avp_hostname = struct.pack(">HHH",
                                       0x8000 | (6 + len(hostname)),
                                       0x0000,
                                       0x0007,  # Attribute Type: Host Name
                                       ) + hostname

            # AVP: Assigned Tunnel ID
            avp_tunnel_id = struct.pack(">HHH",
                                        0x8008,  # M bit set, length 8 (6 header + 2 value)
                                        0x0000,
                                        0x0009,  # Attribute Type: Assigned Tunnel ID
                                        ) + struct.pack(">H", 1)

            payload = avp_msg_type + avp_proto_ver + avp_framing + avp_hostname + avp_tunnel_id

            # Total length including header (12 bytes)
            total_length = 12 + len(payload)

            header = struct.pack(">HHHH",
                                 flags_ver,
                                 total_length,
                                 tunnel_id,
                                 session_id,
                                 ) + struct.pack(">HH", ns, nr)

            packet = header + payload

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            # Parse L2TP response header
            resp_flags = struct.unpack(">H", data[0:2])[0]

            # Check it's a control message (T bit set in flags)
            if not (resp_flags & 0x8000):
                return None

            # Check version (lower bits should be 2)
            if (resp_flags & 0x000F) != 2:
                return None

            metadata: dict = {}

            # Parse AVPs to find message type
            # Skip header (12 bytes for control messages with L and S bits)
            avp_offset = 12
            while avp_offset + 6 <= len(data):
                avp_header = struct.unpack(">H", data[avp_offset:avp_offset + 2])[0]
                avp_len = avp_header & 0x03FF  # lower 10 bits
                if avp_len < 6:
                    break

                vendor_id = struct.unpack(">H", data[avp_offset + 2:avp_offset + 4])[0]
                attr_type = struct.unpack(">H", data[avp_offset + 4:avp_offset + 6])[0]

                # Message Type AVP (vendor=0, type=0)
                if vendor_id == 0 and attr_type == 0 and avp_len >= 8:
                    msg_type = struct.unpack(">H", data[avp_offset + 6:avp_offset + 8])[0]
                    metadata["message_type"] = msg_type
                    # Type 2 = SCCRP (Start-Control-Connection-Reply)
                    if msg_type == 2:
                        metadata["response"] = "SCCRP"

                # Protocol Version AVP (vendor=0, type=2)
                if vendor_id == 0 and attr_type == 2 and avp_len >= 8:
                    ver_major = data[avp_offset + 6]
                    ver_minor = data[avp_offset + 7]
                    metadata["protocol_version"] = f"{ver_major}.{ver_minor}"

                # Host Name AVP (vendor=0, type=7)
                if vendor_id == 0 and attr_type == 7 and avp_len > 6:
                    hostname_bytes = data[avp_offset + 6:avp_offset + avp_len]
                    metadata["hostname"] = hostname_bytes.decode("utf-8", errors="replace")

                avp_offset += avp_len

            # Check for SCCRP response
            if metadata.get("message_type") == 2:
                return ServiceIdentity(
                    service="l2tp",
                    certainty=85,
                    version=metadata.get("protocol_version"),
                    metadata=metadata,
                )

            # Got a valid L2TP control message but not SCCRP
            if metadata.get("message_type") is not None:
                return ServiceIdentity(
                    service="l2tp",
                    certainty=75,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
