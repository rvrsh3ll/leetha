"""EPICS Channel Access probe plugin — scientific/accelerator control."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

# Channel Access commands
_CA_PROTO_VERSION = 0
_CA_PROTO_SEARCH = 6
_CA_PROTO_NOT_FOUND = 14

class EPICSProbePlugin(ServiceProbe):
    name = "epics"
    protocol = "tcp"
    default_ports = [5064, 5065]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send CA_PROTO_VERSION message
            # Header: command(2) + payload_size(2) + data_type(2) + data_count(2)
            #         + param1(4) + param2(4) = 16 bytes
            version_msg = struct.pack(
                ">HHHH II",
                _CA_PROTO_VERSION,  # command
                0,                  # payload size
                0,                  # priority (minor version)
                13,                 # CA protocol version
                0,                  # CID
                0,                  # unused
            )
            conn.write(version_msg)
            data = conn.read(4096)
            if not data or len(data) < 16:
                return None

            # Parse CA header
            cmd = struct.unpack(">H", data[0:2])[0]

            if cmd not in (_CA_PROTO_VERSION, _CA_PROTO_SEARCH, _CA_PROTO_NOT_FOUND):
                return None

            metadata: dict = {}
            version = None

            if cmd == _CA_PROTO_VERSION:
                minor_ver = struct.unpack(">H", data[6:8])[0]
                metadata["ca_minor_version"] = minor_ver
                version = f"CA {minor_ver}"

            metadata["response_command"] = cmd
            return ServiceIdentity(
                service="epics",
                certainty=85,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None
