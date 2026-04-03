"""SMB probe plugin — SMB2 Negotiate to detect SMB/CIFS services."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SMBProbePlugin(ServiceProbe):
    name = "smb"
    protocol = "tcp"
    default_ports = [445, 139]

    # SMB2 dialect revision mapping
    _DIALECTS = {
        0x0202: "2.0.2",
        0x0210: "2.1",
        0x0300: "3.0",
        0x0302: "3.0.2",
        0x0311: "3.1.1",
    }

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build SMB2 Negotiate Request
            # SMB2 header (64 bytes)
            smb2_header = bytearray(64)
            smb2_header[0:4] = b"\xfeSMB"  # Protocol ID
            smb2_header[4:6] = struct.pack("<H", 64)  # Structure size
            # Command: Negotiate (0x0000) at offset 12
            struct.pack_into("<H", smb2_header, 12, 0x0000)
            # Message ID at offset 24
            struct.pack_into("<Q", smb2_header, 24, 0)

            # Negotiate request body
            # StructureSize(2) + DialectCount(2) + SecurityMode(2) + Reserved(2)
            # + Capabilities(4) + ClientGUID(16) + NegotiateContextOffset(4)
            # + NegotiateContextCount(2) + Reserved2(2) + Dialects(variable)
            dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
            dialect_count = len(dialects)
            negotiate_body = struct.pack("<H", 36)  # StructureSize
            negotiate_body += struct.pack("<H", dialect_count)  # DialectCount
            negotiate_body += struct.pack("<H", 1)  # SecurityMode: signing enabled
            negotiate_body += struct.pack("<H", 0)  # Reserved
            negotiate_body += struct.pack("<I", 0)  # Capabilities
            negotiate_body += b"\x00" * 16  # ClientGUID
            negotiate_body += struct.pack("<I", 0)  # NegotiateContextOffset
            negotiate_body += struct.pack("<H", 0)  # NegotiateContextCount
            negotiate_body += struct.pack("<H", 0)  # Reserved2
            for d in dialects:
                negotiate_body += struct.pack("<H", d)

            # NetBIOS session header (4 bytes)
            smb2_msg = bytes(smb2_header) + negotiate_body
            netbios_header = struct.pack(">I", len(smb2_msg))
            packet = netbios_header + smb2_msg

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 68:
                return None

            # Skip NetBIOS header (4 bytes), check SMB2 magic
            offset = 4
            if data[offset:offset + 4] != b"\xfeSMB":
                return None

            # Check command is Negotiate response (0x0000)
            cmd = struct.unpack_from("<H", data, offset + 12)[0]
            if cmd != 0x0000:
                return None

            metadata: dict = {}

            # Parse negotiate response body (starts at offset + 64)
            body_offset = offset + 64
            if len(data) >= body_offset + 4:
                # Dialect revision is at body offset + 4
                if len(data) >= body_offset + 6:
                    dialect_rev = struct.unpack_from("<H", data, body_offset + 4)[0]
                    dialect_str = self._DIALECTS.get(dialect_rev)
                    if dialect_str:
                        metadata["dialect"] = dialect_str
                    else:
                        metadata["dialect"] = f"0x{dialect_rev:04x}"

                # Security mode at body offset + 2
                if len(data) >= body_offset + 4:
                    sec_mode = struct.unpack_from("<H", data, body_offset + 2)[0]
                    metadata["signing_required"] = bool(sec_mode & 0x02)

            version = metadata.get("dialect")
            return ServiceIdentity(
                service="smb",
                certainty=90,
                version=version,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
