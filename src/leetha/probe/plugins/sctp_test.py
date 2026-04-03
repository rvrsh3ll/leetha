"""SCTP/M3UA probe plugin — M3UA ASP Up message for SS7/SIGTRAN detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SCTPTestProbePlugin(ServiceProbe):
    name = "sctp_test"
    protocol = "tcp"
    default_ports = [2905, 14001]

    # M3UA message classes and types
    _MSG_CLASS_ASPM = 3    # ASP State Maintenance
    _MSG_TYPE_ASP_UP = 1
    _MSG_TYPE_ASP_UP_ACK = 4

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build M3UA ASP Up message
            # Common header: version(1) + reserved(1) + message_class(1) + message_type(1) + message_length(4)
            # No parameters for ASP Up
            msg_length = 8  # Just the header
            header = struct.pack("B", 1)  # Version 1
            header += struct.pack("B", 0)  # Reserved
            header += struct.pack("B", self._MSG_CLASS_ASPM)  # Message class: ASPM
            header += struct.pack("B", self._MSG_TYPE_ASP_UP)  # Message type: ASP Up
            header += struct.pack(">I", msg_length)  # Message length

            conn.write(header)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Parse M3UA response header
            resp_version = data[0]
            if resp_version != 1:
                return None

            resp_class = data[2]
            resp_type = data[3]
            resp_length = struct.unpack(">I", data[4:8])[0]

            metadata: dict = {
                "version": resp_version,
                "message_class": resp_class,
                "message_type": resp_type,
                "message_length": resp_length,
            }

            # Check for ASP Up Ack
            if resp_class == self._MSG_CLASS_ASPM and resp_type == self._MSG_TYPE_ASP_UP_ACK:
                metadata["response"] = "ASP Up Ack"
                return ServiceIdentity(
                    service="sctp_test",
                    certainty=75,
                    metadata=metadata,
                )

            # Any M3UA ASPM response indicates the service
            if resp_class == self._MSG_CLASS_ASPM:
                metadata["response"] = f"ASPM_type_{resp_type}"
                return ServiceIdentity(
                    service="sctp_test",
                    certainty=60,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
