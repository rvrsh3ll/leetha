"""MQTT probe plugin — CONNECT packet."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MQTTProbePlugin(ServiceProbe):
    name = "mqtt"
    protocol = "tcp"
    default_ports = [1883, 8883]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # MQTT CONNECT packet (minimal)
            client_id = b"leetha"
            connect = (
                b"\x10"  # CONNECT packet type
                + bytes([12 + len(client_id)])  # Remaining length
                + b"\x00\x04MQTT"  # Protocol name
                + b"\x04"  # Protocol level (v3.1.1)
                + b"\x02"  # Connect flags (clean session)
                + b"\x00\x3c"  # Keep alive: 60s
                + struct.pack(">H", len(client_id)) + client_id
            )
            conn.write(connect)
            data = conn.read(1024)
            if not data or len(data) < 4:
                return None
            # CONNACK: type 0x20
            if data[0] == 0x20:
                return_code = data[3] if len(data) > 3 else -1
                metadata = {"return_code": return_code, "version": "3.1.1"}
                return ServiceIdentity(service="mqtt", certainty=90, metadata=metadata)
            return None
        except (socket.timeout, OSError):
            return None
