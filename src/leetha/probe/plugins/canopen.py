"""CANopen via Ethernet Gateway probe plugin — SDO upload for Identity Object."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CANopenProbePlugin(ServiceProbe):
    name = "canopen"
    protocol = "tcp"
    default_ports = [11898]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build SDO upload request for Object 0x1018 (Identity), subindex 1 (Vendor ID)
            # SDO client CS: 0x40 (initiate upload), index 0x1018 LE, subindex 0x01
            sdo_data = struct.pack("<BHB", 0x40, 0x1018, 0x01)
            sdo_data += b"\x00" * (8 - len(sdo_data))  # Pad to 8 bytes

            # Wrap in CAN-over-Ethernet frame:
            # length(2) + seq(2) + cob_id(4) + dlc(1) + data(8)
            # COB-ID for SDO request to node 1 = 0x601
            cob_id = 0x00000601
            dlc = 8
            frame_payload = struct.pack(">I", cob_id) + struct.pack("B", dlc) + sdo_data
            frame_length = len(frame_payload)
            seq = 0x0001
            request = struct.pack(">HH", frame_length, seq) + frame_payload

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 17:
                return None

            # Parse CAN-over-Ethernet response
            resp_length, resp_seq = struct.unpack(">HH", data[0:4])
            resp_cob_id = struct.unpack(">I", data[4:8])[0]
            resp_dlc = data[8]

            # COB-ID should be 0x581-0x5FF (SDO response)
            if not (0x581 <= resp_cob_id <= 0x5FF):
                return None

            # Parse SDO response data (starts at offset 9)
            sdo_resp = data[9:17]
            if len(sdo_resp) < 8:
                return None

            cs = sdo_resp[0]
            # Check for expedited upload response: CS & 0xE3 == 0x43
            if (cs & 0xE3) != 0x43:
                return None

            # Extract vendor_id from bytes 4-7 (little-endian uint32)
            vendor_id = struct.unpack("<I", sdo_resp[4:8])[0]

            node_id = resp_cob_id - 0x580

            metadata = {
                "cob_id": resp_cob_id,
                "node_id": node_id,
                "vendor_id": vendor_id,
            }

            return ServiceIdentity(
                service="canopen",
                certainty=85,
                version=None,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None
