"""BACnet/IP probe plugin — ReadProperty for Device Object Identifier."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class BACnetProbePlugin(ServiceProbe):
    name = "bacnet"
    protocol = "udp"
    default_ports = [47808]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build BACnet ReadProperty request for Device Object Identifier
            # BVLC header
            bvlc_type = 0x81        # BACnet/IP
            bvlc_function = 0x0A    # Original-Unicast-NPDU
            # NPDU
            npdu_version = 0x01
            npdu_control = 0x04     # Expecting reply

            # APDU: Confirmed-Request, ReadProperty
            # PDU type = 0 (confirmed request), max-segs=0, max-resp=5 (1476 octets)
            apdu = bytes([
                0x00,       # PDU type: Confirmed-Request
                0x05,       # Max APDU size accepted: 1476
                0x01,       # Invoke ID
                0x0C,       # Service choice: ReadProperty (12)
                # Object identifier: Device, instance 4194303 (wildcard-ish)
                0xC4,       # Context tag 0, constructed=1, class=context
                0x02, 0x00, 0x00, 0x00,  # Device object type (8) + instance 0
                # Property identifier: object-identifier (75 = 0x4B)
                0x19, 0x4B,
            ])

            npdu = bytes([npdu_version, npdu_control])
            payload = npdu + apdu
            bvlc_length = 4 + len(payload)
            bvlc = struct.pack(">BBH", bvlc_type, bvlc_function, bvlc_length)
            packet = bvlc + payload

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Validate BVLC header
            if data[0] != 0x81:
                return None

            metadata = {}
            bvlc_func = data[1]
            metadata["bvlc_function"] = bvlc_func

            # Parse NPDU (starts at byte 4)
            npdu_offset = 4
            if npdu_offset >= len(data):
                return None
            resp_npdu_version = data[npdu_offset]
            if resp_npdu_version != 0x01:
                return None

            metadata["npdu_version"] = resp_npdu_version

            # Parse APDU (after NPDU, at least 2 bytes for version+control)
            apdu_offset = npdu_offset + 2
            resp_control = data[npdu_offset + 1]
            # If DNET/DADDR/SNET/SADDR present, skip them
            if resp_control & 0x08:  # Source specifier
                if apdu_offset + 2 > len(data):
                    return ServiceIdentity(
                        service="bacnet", certainty=85, metadata=metadata
                    )
                snet = struct.unpack(">H", data[apdu_offset:apdu_offset + 2])[0]
                metadata["source_network"] = snet
                apdu_offset += 2
                if apdu_offset >= len(data):
                    return ServiceIdentity(
                        service="bacnet", certainty=85, metadata=metadata
                    )
                slen = data[apdu_offset]
                apdu_offset += 1 + slen
                # Hop count
                apdu_offset += 1

            if apdu_offset >= len(data):
                return ServiceIdentity(
                    service="bacnet", certainty=85, metadata=metadata
                )

            # APDU: check PDU type
            apdu_type = (data[apdu_offset] >> 4) & 0x0F
            metadata["apdu_type"] = apdu_type

            # Try to extract device ID from the response payload
            self._parse_device_info(data, apdu_offset, metadata)

            return ServiceIdentity(
                service="bacnet",
                certainty=85,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_device_info(self, data: bytes, apdu_offset: int, metadata: dict) -> None:
        """Attempt to parse device object identifier and vendor from APDU."""
        try:
            # Scan for BACnet object identifier encoding in the response
            remaining = data[apdu_offset:]
            for i in range(len(remaining) - 4):
                # Look for context tag that might contain device object ID
                tag = remaining[i]
                # Application tag 12 (object-identifier) = 0xC4
                if tag == 0xC4 and i + 4 < len(remaining):
                    obj_raw = struct.unpack(">I", remaining[i + 1:i + 5])[0]
                    obj_type = (obj_raw >> 22) & 0x3FF
                    obj_instance = obj_raw & 0x3FFFFF
                    metadata["object_type"] = obj_type
                    metadata["device_id"] = obj_instance
                    break

            # Look for vendor ID (context tag with value for unsigned int)
            for i in range(len(remaining) - 2):
                # Application tag 2 (unsigned) = 0x21 (1 byte) or 0x22 (2 bytes)
                if remaining[i] == 0x22 and i + 2 < len(remaining):
                    vendor_id = struct.unpack(">H", remaining[i + 1:i + 3])[0]
                    if 0 < vendor_id < 1000:  # reasonable vendor ID range
                        metadata["vendor_id"] = vendor_id
                        break
                elif remaining[i] == 0x21 and i + 1 < len(remaining):
                    vendor_id = remaining[i + 1]
                    if 0 < vendor_id < 256:
                        metadata["vendor_id"] = vendor_id
                        break
        except (IndexError, struct.error):
            pass
