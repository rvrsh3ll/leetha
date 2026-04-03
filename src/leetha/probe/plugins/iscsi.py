"""iSCSI probe plugin — Login Request to detect iSCSI targets."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ISCSIProbePlugin(ServiceProbe):
    name = "iscsi"
    protocol = "tcp"
    default_ports = [3260]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build iSCSI Login Request PDU
            # BHS (Basic Header Segment) = 48 bytes
            bhs = bytearray(48)

            # Byte 0: opcode 0x03 (Login Request) with immediate bit (0x40)
            bhs[0] = 0x43  # 0x40 | 0x03
            # Byte 1: flags - T=1 (transit), C=0, CSG=0 (SecurityNegotiation), NSG=1
            bhs[1] = 0x81  # Transit bit + NSG=LoginOperationalNegotiation
            # Byte 2: Version-max
            bhs[2] = 0x00
            # Byte 3: Version-min
            bhs[3] = 0x00

            # Data segment with initiator name
            data_segment = b"InitiatorName=iqn.2024-01.com.leetha:probe\x00"
            data_len = len(data_segment)

            # Bytes 5-7: Data segment length (AHS length at byte 4 = 0)
            bhs[4] = 0  # AHS length
            bhs[5] = (data_len >> 16) & 0xFF
            bhs[6] = (data_len >> 8) & 0xFF
            bhs[7] = data_len & 0xFF

            # ISID (bytes 8-13): initiator session ID
            bhs[8] = 0x40  # Type: random
            bhs[9] = 0x00
            bhs[10] = 0x00
            bhs[11] = 0x01
            bhs[12] = 0x00
            bhs[13] = 0x00

            # CmdSN at bytes 24-27
            struct.pack_into(">I", bhs, 24, 1)
            # ExpStatSN at bytes 28-31
            struct.pack_into(">I", bhs, 28, 0)

            # Pad data segment to 4-byte boundary
            padding = (4 - (data_len % 4)) % 4
            packet = bytes(bhs) + data_segment + b"\x00" * padding

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 48:
                return None

            # Parse iSCSI Login Response
            opcode = data[0] & 0x3F
            if opcode != 0x23:  # Login Response opcode
                return None

            metadata: dict = {}

            # Parse status
            status_class = data[36]
            status_detail = struct.unpack_from(">H", data, 37)[0]
            metadata["status_class"] = status_class
            metadata["status_detail"] = status_detail

            # Parse version
            version_max = data[2]
            version_min = data[3]
            metadata["version_max"] = version_max
            metadata["version_min"] = version_min

            # Parse data segment for key=value pairs
            data_seg_len = (data[5] << 16) | (data[6] << 8) | data[7]
            if data_seg_len > 0 and len(data) >= 48 + data_seg_len:
                text_data = data[48:48 + data_seg_len].decode(
                    "utf-8", errors="replace"
                )
                pairs = text_data.strip("\x00").split("\x00")
                for pair in pairs:
                    if "=" in pair:
                        key, _, value = pair.partition("=")
                        if key == "TargetName" or key == "TargetAddress":
                            metadata[key] = value

            return ServiceIdentity(
                service="iscsi",
                certainty=85,
                version=None,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
