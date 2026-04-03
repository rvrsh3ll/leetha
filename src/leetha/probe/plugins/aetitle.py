"""DICOM AE Title verification probe plugin."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class AETitleProbePlugin(ServiceProbe):
    name = "aetitle"
    protocol = "tcp"
    default_ports = [104]

    _VERIF_UID = b"1.2.840.10008.1.1"
    _IMPL_VR_LE = b"1.2.840.10008.1.2"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            pdu = self._build_associate_rq()
            conn.write(pdu)
            data = conn.read(4096)
            if not data or len(data) < 6:
                return None

            pdu_type = data[0]
            metadata: dict = {}

            if pdu_type == 0x02:
                # A-ASSOCIATE-AC
                self._parse_ac(data, metadata)
                metadata["association"] = "accepted"
                return ServiceIdentity(
                    service="aetitle",
                    certainty=90,
                    metadata=metadata,
                )

            if pdu_type == 0x03:
                # A-ASSOCIATE-RJ
                metadata["association"] = "rejected"
                if len(data) >= 10:
                    metadata["result"] = data[7]
                    metadata["source"] = data[8]
                    metadata["reason"] = data[9]
                return ServiceIdentity(
                    service="aetitle",
                    certainty=85,
                    metadata=metadata,
                )

            return None

        except (socket.timeout, OSError, struct.error):
            return None

    def _build_associate_rq(self) -> bytes:
        """Build A-ASSOCIATE-RQ with specific AE titles for probing."""
        called_ae = b"ANYSCP          "   # 16 bytes
        calling_ae = b"LEETHA           "   # 16 bytes
        reserved32 = b"\x00" * 32

        app_ctx_uid = b"1.2.840.10008.3.1.1.1"
        app_ctx_item = struct.pack(
            ">BBH", 0x10, 0x00, len(app_ctx_uid)
        ) + app_ctx_uid

        abs_syntax_item = struct.pack(
            ">BBH", 0x30, 0x00, len(self._VERIF_UID)
        ) + self._VERIF_UID
        ts_item = struct.pack(
            ">BBH", 0x40, 0x00, len(self._IMPL_VR_LE)
        ) + self._IMPL_VR_LE
        pc_content = bytes([0x01, 0x00, 0x00, 0x00]) + abs_syntax_item + ts_item
        pres_ctx_item = struct.pack(
            ">BBH", 0x20, 0x00, len(pc_content)
        ) + pc_content

        # Implementation class UID sub-item
        impl_uid = b"1.2.826.0.1.3680043.8.1055.1"
        impl_uid_sub = struct.pack(
            ">BBH", 0x52, 0x00, len(impl_uid)
        ) + impl_uid

        max_length_sub = struct.pack(">BBH I", 0x51, 0x00, 4, 16384)
        user_info_content = max_length_sub + impl_uid_sub
        user_info = struct.pack(
            ">BBH", 0x50, 0x00, len(user_info_content)
        ) + user_info_content

        body = (
            struct.pack(">H", 1)
            + b"\x00\x00"
            + called_ae
            + calling_ae
            + reserved32
            + app_ctx_item
            + pres_ctx_item
            + user_info
        )

        header = struct.pack(">BBi", 0x01, 0x00, len(body))
        return header + body

    def _parse_ac(self, data: bytes, metadata: dict) -> None:
        """Parse A-ASSOCIATE-AC for AE title information."""
        if len(data) >= 74:
            called_ae = data[10:26].decode("ascii", errors="replace").strip()
            calling_ae = data[26:42].decode("ascii", errors="replace").strip()
            if called_ae:
                metadata["called_ae"] = called_ae
            if calling_ae:
                metadata["calling_ae"] = calling_ae

        # Scan for Implementation Class UID sub-item (0x52)
        pos = 74
        while pos + 4 < len(data):
            item_type = data[pos]
            if pos + 4 > len(data):
                break
            item_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            if item_type == 0x52 and pos + 4 + item_len <= len(data):
                impl_uid = data[pos + 4:pos + 4 + item_len].decode(
                    "ascii", errors="replace"
                ).strip()
                metadata["implementation_uid"] = impl_uid
                break
            pos += 4 + item_len
