"""OpenVPN probe plugin — sends P_CONTROL_HARD_RESET_CLIENT_V2 packet."""
from __future__ import annotations
import os
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OpenVPNProbePlugin(ServiceProbe):
    name = "openvpn"
    protocol = "udp"
    default_ports = [1194]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 packet
            # Opcode: 0x38 = (7 << 3) where 7 = P_CONTROL_HARD_RESET_CLIENT_V2
            # Key ID is 0 (lower 3 bits)
            opcode_byte = 0x38  # P_CONTROL_HARD_RESET_CLIENT_V2
            session_id = os.urandom(8)  # Random 8-byte session ID
            # HMAC placeholder (empty for initial packet without TLS auth)
            # Packet ID (4 bytes, replay protection)
            packet_id = struct.pack(">I", 0)
            # Net time (optional, not always present)
            # ACK array length = 0
            ack_len = b"\x00"
            # Remote session ID not included for initial reset
            # Message packet ID
            msg_packet_id = struct.pack(">I", 0)

            packet = bytes([opcode_byte]) + session_id + ack_len + msg_packet_id

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 2:
                return None

            # Check for P_CONTROL_HARD_RESET_SERVER_V2 response
            # Opcode 0x40 = (8 << 3) where 8 = P_CONTROL_HARD_RESET_SERVER_V2
            resp_opcode = data[0] & 0xF8  # upper 5 bits
            if resp_opcode == 0x40:
                metadata: dict = {"opcode": "P_CONTROL_HARD_RESET_SERVER_V2"}
                # Extract server session ID (bytes 1-8)
                if len(data) >= 9:
                    server_session = data[1:9].hex()
                    metadata["server_session_id"] = server_session
                return ServiceIdentity(
                    service="openvpn",
                    certainty=85,
                    metadata=metadata,
                )
            return None
        except (socket.timeout, OSError):
            return None
