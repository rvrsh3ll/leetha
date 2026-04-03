"""DICOM probe plugin — A-ASSOCIATE handshake for medical imaging."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DICOMProbePlugin(ServiceProbe):
    name = "dicom"
    protocol = "tcp"
    default_ports = [104, 11112]

    # Verification SOP Class UID
    _VERIF_UID = b"1.2.840.10008.1.1"
    # Default transfer syntax: Implicit VR Little Endian
    _IMPL_VR_LE = b"1.2.840.10008.1.2"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            pdu = self._build_associate_rq()
            conn.write(pdu)
            data = conn.read(4096)
            if not data or len(data) < 6:
                return None

            pdu_type = data[0]

            # A-ASSOCIATE-AC (accepted)
            if pdu_type == 0x02:
                metadata = self._parse_associate_ac(data)
                return ServiceIdentity(
                    service="dicom",
                    certainty=95,
                    metadata=metadata,
                )

            # A-ASSOCIATE-RJ (rejected) — still confirms DICOM
            if pdu_type == 0x03:
                metadata: dict = {"rejected": True}
                if len(data) >= 10:
                    metadata["result"] = data[7]
                    metadata["source"] = data[8]
                    metadata["reason"] = data[9]
                return ServiceIdentity(
                    service="dicom",
                    certainty=85,
                    metadata=metadata,
                )

            return None

        except (socket.timeout, OSError, struct.error):
            return None

    def _build_associate_rq(self) -> bytes:
        """Build a minimal A-ASSOCIATE-RQ PDU (type 0x01)."""
        called_ae = b"ANY-SCP         "   # 16 bytes, padded
        calling_ae = b"LEETHA-SCU       "   # 16 bytes, padded
        reserved32 = b"\x00" * 32

        # Application context item
        app_ctx_uid = b"1.2.840.10008.3.1.1.1"
        app_ctx_item = struct.pack(
            ">BBH", 0x10, 0x00, len(app_ctx_uid)
        ) + app_ctx_uid

        # Presentation context item: Verification SOP + Implicit VR LE
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

        # User information item (minimal)
        max_length_sub = struct.pack(">BBH I", 0x51, 0x00, 4, 16384)
        user_info = struct.pack(
            ">BBH", 0x50, 0x00, len(max_length_sub)
        ) + max_length_sub

        # PDU body
        body = (
            struct.pack(">H", 1)    # protocol version
            + b"\x00\x00"           # reserved
            + called_ae
            + calling_ae
            + reserved32
            + app_ctx_item
            + pres_ctx_item
            + user_info
        )

        # PDU header: type(1) + reserved(1) + length(4)
        header = struct.pack(">BBi", 0x01, 0x00, len(body))
        return header + body

    def _parse_associate_ac(self, data: bytes) -> dict:
        """Extract basic info from an A-ASSOCIATE-AC PDU."""
        metadata: dict = {"accepted": True}
        if len(data) >= 74:
            called_ae = data[10:26].decode("ascii", errors="replace").strip()
            calling_ae = data[26:42].decode("ascii", errors="replace").strip()
            if called_ae:
                metadata["called_ae"] = called_ae
            if calling_ae:
                metadata["calling_ae"] = calling_ae
        return metadata
