"""NDMP probe plugin — Network Data Management Protocol."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

# NDMP magic
_NDMP_MAGIC = 0x00000C00
# Message types
_NDMP_CONNECT_OPEN = 0x0900
_NDMP_CONNECT_SERVER_AUTH = 0x090F
_NDMP_NOTIFY_CONNECTED = 0x0502

class NDMPProbePlugin(ServiceProbe):
    name = "ndmp"
    protocol = "tcp"
    default_ports = [10000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # NDMP servers typically send a NOTIFY_CONNECTED on connect
            # Wait for the banner first
            data = conn.read(4096)
            if not data or len(data) < 24:
                return None

            # Check for NDMP record header
            # Fragment header (4 bytes): last-fragment bit + length
            offset = 0
            if len(data) >= 4:
                frag_raw = struct.unpack(">I", data[0:4])[0]
                if frag_raw & 0x80000000:
                    offset = 4

            if offset + 24 > len(data):
                return None

            # NDMP message header:
            # sequence(4) + time_stamp(4) + message_type(4) + message_code(4)
            # + reply_sequence(4) + error(4)
            sequence = struct.unpack(">I", data[offset:offset + 4])[0]
            timestamp = struct.unpack(">I", data[offset + 4:offset + 8])[0]
            msg_type = struct.unpack(">I", data[offset + 8:offset + 12])[0]
            msg_code = struct.unpack(">I", data[offset + 12:offset + 16])[0]

            # Validate: message_type should be 0 (request) or 1 (reply)
            # and msg_code should be a known NDMP message
            if msg_type not in (0, 1):
                return None

            # Check for known NDMP message codes
            known_codes = {_NDMP_CONNECT_OPEN, _NDMP_CONNECT_SERVER_AUTH,
                           _NDMP_NOTIFY_CONNECTED, 0x0108, 0x0501}
            if msg_code not in known_codes and msg_code > 0x1000:
                return None

            metadata: dict = {
                "sequence": sequence,
                "message_type": msg_type,
                "message_code": msg_code,
            }

            # Try to extract version from NOTIFY_CONNECTED body
            version = None
            body_offset = offset + 24
            if msg_code == _NDMP_NOTIFY_CONNECTED and body_offset + 8 <= len(data):
                reason = struct.unpack(
                    ">I", data[body_offset:body_offset + 4]
                )[0]
                proto_ver = struct.unpack(
                    ">I", data[body_offset + 4:body_offset + 8]
                )[0]
                metadata["reason"] = reason
                metadata["protocol_version"] = proto_ver
                version = f"NDMPv{proto_ver}"

            return ServiceIdentity(
                service="ndmp",
                certainty=85,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None
