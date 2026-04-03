"""PPTP probe plugin — sends Start-Control-Connection-Request."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PPTPProbePlugin(ServiceProbe):
    name = "pptp"
    protocol = "tcp"
    default_ports = [1723]

    # PPTP magic cookie
    MAGIC_COOKIE = 0x1A2B3C4D

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build PPTP Start-Control-Connection-Request (SCCRQ)
            # Control message type 1 = SCCRQ
            # PPTP version 1.0
            # Framing capabilities, bearer capabilities, max channels, firmware rev
            # Host name (64 bytes), vendor (64 bytes)

            hostname = b"leetha" + b"\x00" * 59  # 64 bytes padded
            vendor = b"leetha" + b"\x00" * 59     # 64 bytes padded

            body = struct.pack(">HH",
                               0x0100,  # Protocol version: 1.0
                               0x0000,  # Reserved
                               )
            body += struct.pack(">I", 0x00000003)  # Framing capabilities (sync + async)
            body += struct.pack(">I", 0x00000003)  # Bearer capabilities (analog + digital)
            body += struct.pack(">H", 0x0000)      # Maximum channels
            body += struct.pack(">H", 0x0001)      # Firmware revision
            body += hostname
            body += vendor

            # PPTP header
            length = 12 + len(body)  # 12 = Length(2) + MsgType(2) + Cookie(4) + CtrlType(2) + Reserved(2)
            header = struct.pack(">H", length)
            header += struct.pack(">H", 1)  # PPTP Message Type: Control (1)
            header += struct.pack(">I", self.MAGIC_COOKIE)
            header += struct.pack(">H", 1)  # Control Message Type: SCCRQ (1)
            header += struct.pack(">H", 0)  # Reserved

            packet = header + body
            conn.write(packet)

            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            # Parse PPTP response header
            resp_length = struct.unpack(">H", data[0:2])[0]
            resp_msg_type = struct.unpack(">H", data[2:4])[0]
            resp_cookie = struct.unpack(">I", data[4:8])[0]
            resp_ctrl_type = struct.unpack(">H", data[8:10])[0]

            # Validate magic cookie
            if resp_cookie != self.MAGIC_COOKIE:
                return None

            # Check message type is Control (1)
            if resp_msg_type != 1:
                return None

            metadata: dict = {
                "control_message_type": resp_ctrl_type,
            }

            # SCCRP = Start-Control-Connection-Reply (type 2)
            if resp_ctrl_type == 2:
                metadata["response"] = "SCCRP"
                # Parse additional fields if available
                if len(data) >= 16:
                    proto_version = struct.unpack(">H", data[12:14])[0]
                    metadata["protocol_version"] = f"{proto_version >> 8}.{proto_version & 0xFF}"
                if len(data) >= 24:
                    # Result code at offset 14 (after reserved at 14)
                    result_code = data[14]
                    metadata["result_code"] = result_code
                # Hostname at offset 28 (64 bytes)
                if len(data) >= 92:
                    host_name = data[28:92].split(b"\x00")[0].decode("utf-8", errors="replace")
                    if host_name:
                        metadata["hostname"] = host_name
                # Vendor at offset 92 (64 bytes)
                if len(data) >= 156:
                    vendor_str = data[92:156].split(b"\x00")[0].decode("utf-8", errors="replace")
                    if vendor_str:
                        metadata["vendor"] = vendor_str

            version = metadata.get("protocol_version")
            return ServiceIdentity(
                service="pptp",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
