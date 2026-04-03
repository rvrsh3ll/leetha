"""CIFS/SMB1 probe plugin — legacy SMB1 protocol detection on NetBIOS port."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CIFSProbePlugin(ServiceProbe):
    name = "cifs"
    protocol = "tcp"
    default_ports = [139]

    # SMB1 magic: 0xFF followed by "SMB"
    _SMB1_MAGIC = b"\xffSMB"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build NetBIOS Session Request + SMB1 Negotiate Protocol
            # NetBIOS Session Request (for conn.port 139)
            # Then SMB1 Negotiate with NT LM 0.12 dialect

            # Build SMB1 Negotiate Protocol Request
            smb_header = bytearray(32)
            smb_header[0:4] = self._SMB1_MAGIC  # Protocol ID
            smb_header[4] = 0x72  # Command: Negotiate Protocol (0x72)
            # Flags at offset 9
            smb_header[9] = 0x08  # Flags: paths are caseless
            # Flags2 at offset 10-11
            struct.pack_into("<H", smb_header, 10, 0xC001)
            # PID at offset 26-27
            struct.pack_into("<H", smb_header, 26, 0x0001)

            # Negotiate body: WordCount(1) + ByteCount(2) + Dialect strings
            dialect = b"\x02NT LM 0.12\x00"
            word_count = bytes([0x00])  # 0 words
            byte_count = struct.pack("<H", len(dialect))
            negotiate_body = word_count + byte_count + dialect

            smb_msg = bytes(smb_header) + negotiate_body

            # NetBIOS session header
            netbios_header = struct.pack(">I", len(smb_msg))
            packet = netbios_header + smb_msg

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 39:
                return None

            # Skip NetBIOS header (4 bytes), check for SMB1 magic
            offset = 4
            if data[offset:offset + 4] != self._SMB1_MAGIC:
                return None

            metadata: dict = {}
            metadata["smb_version"] = "SMB1"

            # Command should be Negotiate response (0x72)
            cmd = data[offset + 4]
            if cmd != 0x72:
                return None

            # Extract dialect index from negotiate response
            word_count_val = data[offset + 32]
            if word_count_val >= 1 and len(data) >= offset + 32 + 1 + 2:
                dialect_index = struct.unpack_from("<H", data, offset + 33)[0]
                metadata["dialect_index"] = dialect_index

            return ServiceIdentity(
                service="cifs",
                certainty=85,
                version="SMB1",
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
