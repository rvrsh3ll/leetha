"""STANAG 4586 (UAV control) probe plugin — detect DLI/CUCS response pattern."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class STANAG4586ProbePlugin(ServiceProbe):
    name = "stanag4586"
    protocol = "tcp"
    default_ports = [4586]

    # STANAG 4586 message IDs for known message types
    _KNOWN_MSG_IDS = {1, 2, 3, 20, 21, 100, 101, 200, 201, 300, 301}

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send a STANAG 4586 DLI status request message
            # Message header: sync(2) + msg_id(4) + msg_length(4) + version(2)
            sync = 0x4586
            msg_id = 1        # Vehicle Discovery request
            msg_length = 12   # header only
            version = 3       # STANAG 4586 Edition 3

            request = struct.pack(">HIIH", sync, msg_id, msg_length, version)
            conn.write(request)

            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            # Parse response header
            resp_sync = struct.unpack(">H", data[0:2])[0]
            if resp_sync != 0x4586:
                return None

            resp_msg_id = struct.unpack(">I", data[2:6])[0]
            resp_msg_len = struct.unpack(">I", data[6:10])[0]
            resp_version = struct.unpack(">H", data[10:12])[0]

            metadata: dict = {
                "message_id": resp_msg_id,
                "message_length": resp_msg_len,
                "edition": resp_version,
            }

            if resp_msg_id in self._KNOWN_MSG_IDS:
                metadata["message_type"] = "known"

            return ServiceIdentity(
                service="stanag4586",
                certainty=85,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
