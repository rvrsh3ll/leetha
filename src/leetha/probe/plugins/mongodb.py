"""MongoDB probe plugin — isMaster command."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MongoDBProbePlugin(ServiceProbe):
    name = "mongodb"
    protocol = "tcp"
    default_ports = [27017]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # MongoDB wire protocol: OP_MSG with isMaster
            # Simplified: just try to read the server's response to garbage
            # MongoDB servers send a specific error that identifies them
            conn.write(b"\x41\x00\x00\x00"  # message length
                        b"\x01\x00\x00\x00"  # request ID
                        b"\x00\x00\x00\x00"  # response to
                        b"\xdd\x07\x00\x00"  # OP_MSG (2013)
                        b"\x00\x00\x00\x00"  # flags
                        b"\x00"              # section kind 0
                        + b'\x24\x00\x00\x00'  # doc size
                        + b'\x01isMaster\x00\x00\x00\x00\x00\x00\xf0?\x02$db\x00\x06\x00\x00\x00admin\x00\x00'
                        )
            data = conn.read(4096)
            if not data or len(data) < 16:
                return None
            # Check for MongoDB wire protocol response
            if len(data) >= 16:
                opcode = struct.unpack("<I", data[12:16])[0]
                if opcode in (1, 2013):  # OP_REPLY or OP_MSG
                    return ServiceIdentity(service="mongodb", certainty=85, metadata={"opcode": opcode})
            return None
        except (socket.timeout, OSError, struct.error):
            return None
