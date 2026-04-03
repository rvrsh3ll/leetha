"""PostgreSQL probe plugin — startup message."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PostgreSQLProbePlugin(ServiceProbe):
    name = "postgresql"
    protocol = "tcp"
    default_ports = [5432]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send SSLRequest
            ssl_request = struct.pack(">II", 8, 80877103)
            conn.write(ssl_request)
            resp = conn.read(1)
            if not resp:
                return None
            # 'N' = no SSL, 'S' = SSL supported
            if resp not in (b'N', b'S'):
                return None
            tls = resp == b'S'
            metadata = {"ssl_supported": tls}
            return ServiceIdentity(service="postgresql", certainty=90, tls=tls, metadata=metadata)
        except (socket.timeout, OSError):
            return None
