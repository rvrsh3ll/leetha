"""EtherNet/IP (CIP) probe plugin — RegisterSession + ListIdentity."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ENIPProbePlugin(ServiceProbe):
    name = "enip"
    protocol = "tcp"
    default_ports = [44818, 2222]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Step 1: Send RegisterSession command (0x0065)
            register_session = self._build_enip_packet(
                command=0x0065,
                session_handle=0x00000000,
                data=struct.pack("<HH", 1, 0),  # protocol version 1, option flags 0
            )
            conn.write(register_session)
            data = conn.read(1024)
            if not data or len(data) < 24:
                return None

            # Parse EtherNet/IP header
            resp_command = struct.unpack("<H", data[0:2])[0]
            resp_status = struct.unpack("<I", data[8:12])[0]

            if resp_command != 0x0065 or resp_status != 0:
                return None

            session_handle = struct.unpack("<I", data[4:8])[0]
            metadata = {"session_handle": session_handle}

            # Step 2: Send ListIdentity command (0x0063)
            list_identity = self._build_enip_packet(
                command=0x0063,
                session_handle=session_handle,
            )
            conn.write(list_identity)

            try:
                id_data = conn.read(4096)
                if id_data and len(id_data) > 24:
                    self._parse_list_identity(id_data, metadata)
            except (socket.timeout, OSError):
                pass  # ListIdentity is best-effort

            version = metadata.get("product_name")
            return ServiceIdentity(
                service="enip",
                certainty=90,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _build_enip_packet(
        self,
        command: int,
        session_handle: int = 0,
        data: bytes = b"",
    ) -> bytes:
        """Build an EtherNet/IP encapsulation packet."""
        header = struct.pack(
            "<HHI4sQ I",
            command,             # Command (2 bytes)
            len(data),           # Length (2 bytes)
            session_handle,      # Session handle (4 bytes)
            b"\x00" * 4,        # Status (4 bytes)
            0,                   # Sender context (8 bytes)
            0,                   # Options (4 bytes)
        )
        return header + data

    def _parse_list_identity(self, data: bytes, metadata: dict) -> None:
        """Parse ListIdentity response to extract device info."""
        try:
            # Skip encapsulation header (24 bytes)
            offset = 24
            if offset + 2 > len(data):
                return
            item_count = struct.unpack("<H", data[offset:offset + 2])[0]
            metadata["item_count"] = item_count
            if item_count < 1:
                return

            offset += 2
            # Skip item type ID (2) + item length (2)
            if offset + 4 > len(data):
                return
            offset += 4

            # CIP Identity item
            if offset + 2 > len(data):
                return
            # Protocol version
            proto_version = struct.unpack("<H", data[offset:offset + 2])[0]
            metadata["protocol_version"] = proto_version
            offset += 2

            # Skip socket address (16 bytes)
            if offset + 16 > len(data):
                return
            offset += 16

            # Vendor ID (2) + Device Type (2) + Product Code (2)
            if offset + 6 > len(data):
                return
            vendor_id = struct.unpack("<H", data[offset:offset + 2])[0]
            device_type = struct.unpack("<H", data[offset + 2:offset + 4])[0]
            product_code = struct.unpack("<H", data[offset + 4:offset + 6])[0]
            metadata["vendor_id"] = vendor_id
            metadata["device_type"] = device_type
            metadata["product_code"] = product_code
            offset += 6

            # Revision (major.minor)
            if offset + 2 > len(data):
                return
            rev_major = data[offset]
            rev_minor = data[offset + 1]
            metadata["revision"] = f"{rev_major}.{rev_minor}"
            offset += 2

            # Status (2) + Serial number (4)
            if offset + 6 > len(data):
                return
            offset += 6

            # Product name (length-prefixed string)
            if offset + 1 > len(data):
                return
            name_len = data[offset]
            offset += 1
            if offset + name_len <= len(data):
                product_name = data[offset:offset + name_len].decode(
                    "utf-8", errors="replace"
                )
                metadata["product_name"] = product_name
        except (IndexError, struct.error):
            pass
