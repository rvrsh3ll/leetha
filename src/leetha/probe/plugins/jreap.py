"""JREAP (Joint Range Extension Applications Protocol) probe plugin — detect JREAP-C header."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class JREAPProbePlugin(ServiceProbe):
    name = "jreap"
    protocol = "tcp"
    default_ports = [5602]

    # JREAP-C magic bytes: "JREAP" in ASCII
    _MAGIC = b"JREAP"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Read initial data from the stream — JREAP-C sends header on connect
            conn.set_timeout(3)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Look for JREAP magic in the data stream
            offset = data.find(self._MAGIC)
            if offset < 0:
                return None

            metadata: dict = {"protocol": "jreap-c"}
            version = None

            # Parse version byte following the magic header
            hdr_start = offset + len(self._MAGIC)
            if hdr_start < len(data):
                ver_byte = data[hdr_start]
                version = str(ver_byte)
                metadata["version_byte"] = ver_byte

            # Parse message length if available (2 bytes after version)
            if hdr_start + 3 <= len(data):
                msg_len = struct.unpack(">H", data[hdr_start + 1:hdr_start + 3])[0]
                metadata["message_length"] = msg_len

            return ServiceIdentity(
                service="jreap",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
