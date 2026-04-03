"""IBM MQ (WebSphere MQ) probe plugin — TSH header detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MQSeriesProbePlugin(ServiceProbe):
    name = "mq_series"
    protocol = "tcp"
    default_ports = [1414]

    # TSH (Transmission Segment Header) magic: "TSH " in ASCII
    _TSH_MAGIC = b"TSH "
    _TSH_MAGIC_INT = 0x54534820

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build an Initial Data (ID) packet with TSH header
            # TSH header: StructId(4) + MQSegmLen(4) + ByteOrder(1) +
            #             SegmType(1) + CtlFlag1(1) + CtlFlag2(1) +
            #             LUWID(24) + Encoding(4) + CCSID(2) + Reserved(2)
            tsh = bytearray(44)
            tsh[0:4] = self._TSH_MAGIC           # StructId
            struct.pack_into(">I", tsh, 4, 44)    # MQSegmLen
            tsh[8] = 0x01                          # ByteOrder (big endian)
            tsh[9] = 0x01                          # SegmType: INITIAL_DATA
            tsh[10] = 0x00                         # CtlFlag1
            tsh[11] = 0x00                         # CtlFlag2
            # LUWID zeroed (24 bytes at offset 12)
            struct.pack_into(">I", tsh, 36, 0x222)  # Encoding
            struct.pack_into(">H", tsh, 40, 1208)   # CCSID (UTF-8)

            conn.write(bytes(tsh))

            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Check for TSH magic in response
            if data[0:4] != self._TSH_MAGIC:
                return None

            metadata: dict = {}

            # Parse TSH response header
            if len(data) >= 12:
                seg_len = struct.unpack(">I", data[4:8])[0]
                metadata["segment_length"] = seg_len
                metadata["byte_order"] = "big_endian" if data[8] == 0x01 else "little_endian"
                metadata["segment_type"] = data[9]

            if len(data) >= 42:
                ccsid = struct.unpack(">H", data[40:42])[0]
                metadata["ccsid"] = ccsid

            return ServiceIdentity(
                service="mq_series",
                certainty=90,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
