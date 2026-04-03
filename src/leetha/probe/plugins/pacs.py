"""PACS probe plugin — Picture Archiving and Communication System via DICOM."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PACSProbePlugin(ServiceProbe):
    name = "pacs"
    protocol = "tcp"
    default_ports = [4242, 11112]

    # SOP Class UIDs indicating PACS functionality
    _STUDY_ROOT_QR_FIND = b"1.2.840.10008.5.1.4.1.2.2.1"
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

            if pdu_type == 0x02:
                metadata = self._parse_associate_ac(data)
                metadata["pacs_detected"] = True
                return ServiceIdentity(
                    service="pacs",
                    certainty=90,
                    metadata=metadata,
                )

            if pdu_type == 0x03:
                metadata: dict = {"rejected": True}
                if len(data) >= 10:
                    metadata["result"] = data[7]
                    metadata["source"] = data[8]
                    metadata["reason"] = data[9]
                return ServiceIdentity(
                    service="pacs",
                    certainty=75,
                    metadata=metadata,
                )

            return None

        except (socket.timeout, OSError, struct.error):
            return None

    def _build_associate_rq(self) -> bytes:
        """Build A-ASSOCIATE-RQ with Study Root QR Find SOP Class."""
        called_ae = b"PACS            "
        calling_ae = b"LEETHA-SCU       "
        reserved32 = b"\x00" * 32

        app_ctx_uid = b"1.2.840.10008.3.1.1.1"
        app_ctx_item = struct.pack(
            ">BBH", 0x10, 0x00, len(app_ctx_uid)
        ) + app_ctx_uid

        # Presentation context 1: Verification SOP
        abs1 = struct.pack(
            ">BBH", 0x30, 0x00, len(self._VERIF_UID)
        ) + self._VERIF_UID
        ts1 = struct.pack(
            ">BBH", 0x40, 0x00, len(self._IMPL_VR_LE)
        ) + self._IMPL_VR_LE
        pc1_content = bytes([0x01, 0x00, 0x00, 0x00]) + abs1 + ts1
        pc1 = struct.pack(">BBH", 0x20, 0x00, len(pc1_content)) + pc1_content

        # Presentation context 2: Study Root QR Find
        abs2 = struct.pack(
            ">BBH", 0x30, 0x00, len(self._STUDY_ROOT_QR_FIND)
        ) + self._STUDY_ROOT_QR_FIND
        ts2 = struct.pack(
            ">BBH", 0x40, 0x00, len(self._IMPL_VR_LE)
        ) + self._IMPL_VR_LE
        pc2_content = bytes([0x03, 0x00, 0x00, 0x00]) + abs2 + ts2
        pc2 = struct.pack(">BBH", 0x20, 0x00, len(pc2_content)) + pc2_content

        max_length_sub = struct.pack(">BBH I", 0x51, 0x00, 4, 16384)
        user_info = struct.pack(
            ">BBH", 0x50, 0x00, len(max_length_sub)
        ) + max_length_sub

        body = (
            struct.pack(">H", 1)
            + b"\x00\x00"
            + called_ae
            + calling_ae
            + reserved32
            + app_ctx_item
            + pc1
            + pc2
            + user_info
        )

        header = struct.pack(">BBi", 0x01, 0x00, len(body))
        return header + body

    def _parse_associate_ac(self, data: bytes) -> dict:
        """Extract AE titles from A-ASSOCIATE-AC."""
        metadata: dict = {"accepted": True}
        if len(data) >= 74:
            called_ae = data[10:26].decode("ascii", errors="replace").strip()
            calling_ae = data[26:42].decode("ascii", errors="replace").strip()
            if called_ae:
                metadata["called_ae"] = called_ae
            if calling_ae:
                metadata["calling_ae"] = calling_ae
        return metadata
