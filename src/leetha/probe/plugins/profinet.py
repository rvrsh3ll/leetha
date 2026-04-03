"""PROFINET DCP probe plugin — DCP Identify request over UDP."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PROFINETProbePlugin(ServiceProbe):
    name = "profinet"
    protocol = "udp"
    default_ports = [34964]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # PROFINET DCP Identify All request
            # FrameID: 0xFEFE (DCP Identify Multicast)
            # ServiceID: 0x05 (Identify)
            # ServiceType: 0x00 (Request)
            # Xid: transaction ID
            # ResponseDelay: 1 (factor)
            # DCPDataLength: 4 (option block length)
            # Option: 0xFF (All), SubOption: 0xFF (All)
            # DCPBlockLength: 0
            xid = 0x00000001
            request = struct.pack(
                ">HBB I HH BB H",
                0xFEFE,     # FrameID
                0x05,       # ServiceID: Identify
                0x00,       # ServiceType: Request
                xid,        # Xid
                0x0001,     # ResponseDelay
                0x0004,     # DCPDataLength
                0xFF,       # Option: All
                0xFF,       # SubOption: All
                0x0000,     # DCPBlockLength
            )

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            # Parse response
            frame_id = struct.unpack(">H", data[0:2])[0]
            # DCP Identify response uses FrameID 0xFEFF
            if frame_id not in (0xFEFE, 0xFEFF):
                return None

            service_id = data[2]
            service_type = data[3]

            # ServiceID should be 0x05 (Identify), ServiceType 0x01 (Response Success)
            if service_id != 0x05:
                return None
            if service_type not in (0x00, 0x01):
                return None

            metadata = {
                "frame_id": frame_id,
                "service_id": service_id,
                "service_type": service_type,
            }

            # Parse Xid from response
            resp_xid = struct.unpack(">I", data[4:8])[0]
            metadata["xid"] = resp_xid

            # Try to parse DCP blocks from the response
            dcp_data_length = struct.unpack(">H", data[10:12])[0]
            self._parse_dcp_blocks(data[12:12 + dcp_data_length], metadata)

            version = metadata.get("device_name") or metadata.get("device_vendor")
            return ServiceIdentity(
                service="profinet",
                certainty=80,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_dcp_blocks(self, data: bytes, metadata: dict) -> None:
        """Parse DCP option blocks from identify response."""
        try:
            offset = 0
            while offset + 4 <= len(data):
                option = data[offset]
                suboption = data[offset + 1]
                block_length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
                offset += 4

                if offset + block_length > len(data):
                    break

                block_data = data[offset:offset + block_length]

                # Option 0x02 = Device properties
                if option == 0x02:
                    if suboption == 0x01 and len(block_data) >= 2:
                        # Device vendor (skip 2-byte block info)
                        metadata["device_vendor"] = block_data[2:].decode(
                            "utf-8", errors="replace"
                        ).rstrip("\x00")
                    elif suboption == 0x02 and len(block_data) >= 2:
                        # Name of station
                        metadata["device_name"] = block_data[2:].decode(
                            "utf-8", errors="replace"
                        ).rstrip("\x00")
                    elif suboption == 0x03 and len(block_data) >= 2:
                        # Device ID
                        if len(block_data) >= 6:
                            vendor_id = struct.unpack(">H", block_data[2:4])[0]
                            device_id = struct.unpack(">H", block_data[4:6])[0]
                            metadata["vendor_id"] = vendor_id
                            metadata["device_id"] = device_id

                # Pad to even boundary
                offset += block_length
                if block_length % 2 != 0:
                    offset += 1
        except (IndexError, struct.error):
            pass
