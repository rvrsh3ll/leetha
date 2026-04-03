"""TANGO Controls probe plugin — scientific instrument control via CORBA/IIOP."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

# GIOP magic and message types
_GIOP_MAGIC = b"GIOP"
_GIOP_REPLY = 1

class TANGOProbePlugin(ServiceProbe):
    name = "tango"
    protocol = "tcp"
    default_ports = [10000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a GIOP 1.2 LocateRequest to check if TANGO DB responds
            giop_msg = self._build_giop_request()
            conn.write(giop_msg)
            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            # Validate GIOP magic
            if data[0:4] != _GIOP_MAGIC:
                return None

            major = data[4]
            minor = data[5]
            msg_type = data[7]

            metadata: dict = {
                "giop_version": f"{major}.{minor}",
                "message_type": msg_type,
            }

            # Check for TANGO-specific content in the payload
            payload = data[12:]
            payload_text = payload.decode("latin-1", errors="replace")
            is_tango = (
                b"tango" in data.lower()
                or b"Tango" in data
                or b"TANGO" in data
                or b"IDL:Tango/" in data
            )

            if is_tango:
                metadata["tango_detected"] = True
                confidence = 90
            else:
                confidence = 70

            version = metadata["giop_version"]

            return ServiceIdentity(
                service="tango",
                certainty=confidence,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _build_giop_request(self) -> bytes:
        """Build a minimal GIOP 1.2 Request message."""
        # GIOP header: magic(4) + version(2) + flags(1) + message_type(1) + size(4)
        # Request message type = 0
        # Minimal request body: request_id(4) + response_expected(1) + padding(3)
        #                       + object_key_length(4) + object_key
        object_key = b"\x00\x00\x00\x00"  # empty key
        operation = b"_non_existent\x00"

        request_body = struct.pack("<I", 1)      # request_id
        request_body += bytes([1, 0, 0, 0])      # response_expected + reserved
        # Target address: KeyAddr type (0) + key length + key
        request_body += struct.pack("<I", len(object_key)) + object_key
        request_body += struct.pack("<I", len(operation)) + operation
        # Service context list (empty)
        request_body += struct.pack("<I", 0)

        body_size = len(request_body)
        header = _GIOP_MAGIC + bytes([1, 2, 1, 0])  # v1.2, little-endian, Request
        header += struct.pack("<I", body_size)

        return header + request_body
