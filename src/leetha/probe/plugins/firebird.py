"""Firebird probe plugin — connection request."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FirebirdProbePlugin(ServiceProbe):
    name = "firebird"
    protocol = "tcp"
    default_ports = [3050]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Firebird wire protocol connection request
            # op_connect = 1
            packet = struct.pack(">I", 1)  # op_connect
            # op_attach operation
            packet += struct.pack(">I", 3)  # op_accept (connect operation)
            # Protocol version info
            packet += struct.pack(">I", 10)  # version 10
            # Architecture type: generic
            packet += struct.pack(">I", 1)  # arch_generic
            # Min type
            packet += struct.pack(">I", 0)  # ptype
            # Max type
            packet += struct.pack(">I", 3)  # ptype_lazy_send
            # Protocol count
            packet += struct.pack(">I", 1)
            # Protocol descriptor: version, arch, min_type, max_type, weight
            packet += struct.pack(">I", 10)  # version
            packet += struct.pack(">I", 1)   # architecture
            packet += struct.pack(">I", 0)   # min type
            packet += struct.pack(">I", 3)   # max type
            packet += struct.pack(">I", 2)   # weight
            # User identification: empty
            packet += struct.pack(">I", 0)   # user ident length

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 4:
                return None

            # Parse response - first 4 bytes is the operation code
            op_code = struct.unpack(">I", data[0:4])[0]

            metadata: dict = {"op_code": op_code}
            version = None

            # op_accept = 3, op_cond_accept = 14, op_accept_data = 15
            if op_code in (3, 14, 15):
                metadata["response"] = "accept"
                if len(data) >= 16:
                    proto_version = struct.unpack(">I", data[4:8])[0]
                    arch = struct.unpack(">I", data[8:12])[0]
                    proto_type = struct.unpack(">I", data[12:16])[0]
                    version = str(proto_version)
                    metadata["protocol_version"] = proto_version
                    metadata["architecture"] = arch
                    metadata["type"] = proto_type
            elif op_code == 9:  # op_reject
                metadata["response"] = "reject"
            else:
                return None

            return ServiceIdentity(
                service="firebird",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
