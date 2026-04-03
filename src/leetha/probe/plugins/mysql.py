"""MySQL probe plugin — server greeting."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MySQLProbePlugin(ServiceProbe):
    name = "mysql"
    protocol = "tcp"
    default_ports = [3306]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data or len(data) < 5:
                return None
            # MySQL greeting: 3-byte length + 1-byte seq + protocol version (0x0a)
            proto_version = data[4]
            if proto_version != 0x0A:
                return None
            # Server version is null-terminated string starting at byte 5
            null_pos = data.find(b'\x00', 5)
            if null_pos == -1:
                return None
            version = data[5:null_pos].decode("utf-8", errors="replace")
            metadata = {"protocol_version": proto_version}
            if "MariaDB" in version:
                metadata["product"] = "MariaDB"
            else:
                metadata["product"] = "MySQL"
            return ServiceIdentity(service="mysql", version=version, certainty=95, metadata=metadata)
        except (socket.timeout, OSError):
            return None
