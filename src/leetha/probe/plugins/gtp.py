"""GTP-C probe plugin — GTPv2 Echo Request for mobile core network detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GTPProbePlugin(ServiceProbe):
    name = "gtp"
    protocol = "udp"
    default_ports = [2123]

    # GTPv2-C message types
    _MSG_ECHO_REQUEST = 1
    _MSG_ECHO_RESPONSE = 2

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build GTPv2-C Echo Request
            # Header: version(3 bits)=2 | P(1 bit)=0 | T(1 bit)=0 | spare(3 bits)=0
            # Message type(1 byte) | Message length(2 bytes) | Sequence number(3 bytes) | Spare(1 byte)
            # Note: When T=0, TEID is not present
            version_flags = (2 << 5)  # Version 2, P=0, T=0, spare=0
            msg_type = self._MSG_ECHO_REQUEST
            seq_num = 0x000001

            # Length is the length of everything after the mandatory 4-byte header
            # = sequence(3) + spare(1) = 4 bytes
            msg_length = 4

            header = struct.pack("B", version_flags)
            header += struct.pack("B", msg_type)
            header += struct.pack(">H", msg_length)
            header += struct.pack(">I", seq_num)[1:]  # 3-byte sequence number
            header += struct.pack("B", 0)  # Spare

            conn.write(header)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Parse GTPv2-C header
            first_byte = data[0]
            resp_version = (first_byte >> 5) & 0x07
            if resp_version != 2:
                return None

            resp_msg_type = data[1]
            resp_length = struct.unpack(">H", data[2:4])[0]

            metadata: dict = {
                "version": resp_version,
                "message_type": resp_msg_type,
                "message_length": resp_length,
            }

            # Check for Echo Response
            if resp_msg_type == self._MSG_ECHO_RESPONSE:
                metadata["response"] = "Echo Response"

                # Try to parse Recovery IE (type 3) if present
                t_flag = (first_byte >> 3) & 0x01
                ie_offset = 8 if t_flag == 0 else 12
                if ie_offset < len(data):
                    ie_data = data[ie_offset:]
                    if len(ie_data) >= 4:
                        ie_type = ie_data[0]
                        ie_length = struct.unpack(">H", ie_data[1:3])[0]
                        if ie_type == 3 and ie_length >= 1 and len(ie_data) > 4:
                            metadata["recovery_counter"] = ie_data[4]

                return ServiceIdentity(
                    service="gtp",
                    certainty=85,
                    metadata=metadata,
                )

            # Any GTPv2 response indicates the service
            return ServiceIdentity(
                service="gtp",
                certainty=70,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
