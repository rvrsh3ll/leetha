"""IBM DB2 probe plugin — DRDA EXCSAT command."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DB2ProbePlugin(ServiceProbe):
    name = "db2"
    protocol = "tcp"
    default_ports = [50000, 50001, 523]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build DRDA EXCSAT (Exchange Server Attributes) command
            # MGRLVLLS (Manager-Level List) parameter
            # Code point 0x1404 = MGRLVLLS
            mgrlvl_data = b""
            # SQLAM level 7
            mgrlvl_data += struct.pack(">HH", 0x1403, 0x0007)  # SQLAM = 7
            # AGENT level 7
            mgrlvl_data += struct.pack(">HH", 0x1403, 0x0007)

            mgrlvlls = struct.pack(">HH", len(mgrlvl_data) + 4, 0x1404) + mgrlvl_data

            # SRVCLSNM (Server Class Name) parameter
            # Code point 0x1147
            class_name = b"QDB2/LINUXX8664"
            srvclsnm = struct.pack(">HH", len(class_name) + 4, 0x1147) + class_name

            # EXCSAT command object
            # Code point 0x1041 = EXCSAT
            excsat_data = mgrlvlls + srvclsnm
            excsat_len = len(excsat_data) + 4
            excsat = struct.pack(">HH", excsat_len, 0x1041) + excsat_data

            # DDM header (DSS = Data Stream Structure)
            # length(2) + magic(1)=0xD0 + format(1)=0x41 + corr_id(2) + ...
            dss_len = len(excsat) + 6
            dss = struct.pack(">H", dss_len)
            dss += bytes([0xD0, 0x41])  # magic + format (request, chain=no)
            dss += struct.pack(">H", 1)  # correlation ID
            dss += excsat

            conn.write(dss)
            data = conn.read(4096)
            if not data or len(data) < 10:
                return None

            # Parse DRDA response
            # Look for EXCSATRD response (code point 0x1443)
            metadata: dict = {}
            version = None
            offset = 0
            found = False

            while offset + 6 <= len(data):
                if offset + 2 > len(data):
                    break
                seg_len = struct.unpack(">H", data[offset:offset + 2])[0]
                if seg_len < 6:
                    break
                # Check for DDM header magic
                if offset + 4 <= len(data) and data[offset + 2] == 0xD0:
                    # Look for code points in this segment
                    inner_offset = offset + 6
                    while inner_offset + 4 <= offset + seg_len:
                        obj_len = struct.unpack(">H", data[inner_offset:inner_offset + 2])[0]
                        if obj_len < 4:
                            break
                        code_point = struct.unpack(">H", data[inner_offset + 2:inner_offset + 4])[0]
                        if code_point == 0x1443:  # EXCSATRD
                            found = True
                            # Try to extract server info from within EXCSATRD
                            self._parse_excsatrd(data[inner_offset + 4:inner_offset + obj_len], metadata)
                            break
                        inner_offset += obj_len
                offset += seg_len

            if not found:
                return None

            version = metadata.get("server_version")
            return ServiceIdentity(
                service="db2",
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
                if cp == 0x115E:  # SRVNAM (Server Name)
                    metadata["server_name"] = field_data.decode("utf-8", errors="replace")
                elif cp == 0x1147:  # SRVCLSNM (Server Class Name)
                    metadata["server_class"] = field_data.decode("utf-8", errors="replace")
                elif cp == 0x115A:  # SRVRLSLV (Server Release Level)
                    metadata["server_version"] = field_data.decode("utf-8", errors="replace")
                offset += field_len
        except Exception:
            pass
