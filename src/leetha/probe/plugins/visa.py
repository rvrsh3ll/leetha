"""VISA/HiSLIP probe plugin — lab instruments via High-Speed LAN Instrument Protocol."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

# HiSLIP message types
_HISLIP_INITIALIZE = 0
_HISLIP_INITIALIZE_RESPONSE = 1
# HiSLIP prologue
_HISLIP_PROLOGUE = b"HS"

class VISAProbePlugin(ServiceProbe):
    name = "visa"
    protocol = "tcp"
    default_ports = [4880]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            init_msg = self._build_hislip_initialize()
            conn.write(init_msg)
            data = conn.read(4096)
            if not data or len(data) < 16:
                return None

            # Validate HiSLIP prologue
            if data[0:2] != _HISLIP_PROLOGUE:
                return None

            msg_type = data[2]
            if msg_type != _HISLIP_INITIALIZE_RESPONSE:
                return None

            metadata: dict = {"hislip_detected": True}

            # Parse Initialize Response
            # Bytes 3: control code
            # Bytes 4-5: overlap mode
            # Bytes 6-7: server protocol version
            # Bytes 8-9: session ID
            if len(data) >= 10:
                proto_major = data[6]
                proto_minor = data[7]
                session_id = struct.unpack(">H", data[8:10])[0]
                metadata["protocol_version"] = f"{proto_major}.{proto_minor}"
                metadata["session_id"] = session_id

            version = metadata.get("protocol_version")

            return ServiceIdentity(
                service="visa",
                certainty=90,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _build_hislip_initialize(self) -> bytes:
        """Build a HiSLIP Initialize message."""
        msg = _HISLIP_PROLOGUE          # prologue "HS"
        msg += bytes([_HISLIP_INITIALIZE])  # message type
        msg += bytes([0])               # control code
        msg += struct.pack(">H", 0)     # overlap mode (Synchronous)
        msg += struct.pack(">BB", 1, 0) # protocol version 1.0
        msg += struct.pack(">H", 0)     # sub-address (0 = default)
        # Payload length (8 bytes for vendor ID field)
        msg += struct.pack(">Q", 0)     # payload length = 0
        return msg
