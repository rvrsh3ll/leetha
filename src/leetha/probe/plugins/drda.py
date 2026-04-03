"""DRDA probe plugin — Distributed Relational Database Architecture detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DRDAProbePlugin(ServiceProbe):
    name = "drda"
    protocol = "tcp"
    default_ports = [50000, 446]

    # DRDA code points
    _EXCSAT = 0x1041   # Exchange Server Attributes
    _EXCSATRD = 0x1443  # EXCSAT Reply Data

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build DRDA EXCSAT (Exchange Server Attributes) command
            # MGRLVLLS (Manager-Level List) parameter
            mgrlvl_data = struct.pack(">HH", 0x1403, 0x0007)  # SQLAM level 7
            mgrlvlls = struct.pack(">HH", len(mgrlvl_data) + 4, 0x1404) + mgrlvl_data

            # SRVCLSNM (Server Class Name)
            class_name = b"LEETHA"
            srvclsnm = struct.pack(">HH", len(class_name) + 4, 0x1147) + class_name

            # EXCSAT command object
            excsat_data = mgrlvlls + srvclsnm
            excsat = struct.pack(">HH", len(excsat_data) + 4, self._EXCSAT) + excsat_data

            # DDM DSS header
            dss_len = len(excsat) + 6
            dss = struct.pack(">H", dss_len)
            dss += bytes([0xD0, 0x41])  # magic + format
            dss += struct.pack(">H", 1)  # correlation ID
            dss += excsat

            conn.write(dss)
            data = conn.read(4096)
            if not data or len(data) < 10:
                return None

            # Parse DRDA response looking for EXCSATRD
            metadata: dict = {}
            version = None
            found = False
            offset = 0

            while offset + 6 <= len(data):
                seg_len = struct.unpack(">H", data[offset:offset + 2])[0]
                if seg_len < 6:
                    break
                if data[offset + 2] == 0xD0:
                    inner_offset = offset + 6
                    while inner_offset + 4 <= offset + seg_len:
                        obj_len = struct.unpack(">H", data[inner_offset:inner_offset + 2])[0]
                        if obj_len < 4:
                            break
                        code_point = struct.unpack(">H", data[inner_offset + 2:inner_offset + 4])[0]
                        if code_point == self._EXCSATRD:
                            found = True
                            self._parse_excsatrd(
                                data[inner_offset + 4:inner_offset + obj_len],
                                metadata,
                            )
                            break
                        inner_offset += obj_len
                offset += seg_len

            if not found:
                return None

            version = metadata.get("server_version")
            return ServiceIdentity(
                service="drda",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None

    @staticmethod
    def _parse_excsatrd(data: bytes, metadata: dict) -> None:
        """Parse fields within EXCSATRD response."""
        offset = 0
        try:
            while offset + 4 <= len(data):
                field_len = struct.unpack(">H", data[offset:offset + 2])[0]
                if field_len < 4:
                    break
                cp = struct.unpack(">H", data[offset + 2:offset + 4])[0]
                field_data = data[offset + 4:offset + field_len]
                if cp == 0x115E:  # SRVNAM
                    metadata["server_name"] = field_data.decode("utf-8", errors="replace")
                elif cp == 0x1147:  # SRVCLSNM
                    metadata["server_class"] = field_data.decode("utf-8", errors="replace")
                elif cp == 0x115A:  # SRVRLSLV
                    metadata["server_version"] = field_data.decode("utf-8", errors="replace")
                offset += field_len
        except Exception:
            pass
