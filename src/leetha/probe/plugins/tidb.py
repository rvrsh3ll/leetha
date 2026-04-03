"""TiDB probe plugin — MySQL wire protocol with TiDB detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TiDBProbePlugin(ServiceProbe):
    name = "tidb"
    protocol = "tcp"
    default_ports = [4000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # TiDB uses MySQL wire protocol and sends greeting on connect
            data = conn.read(1024)
            if not data or len(data) < 5:
                return None

            # MySQL greeting: 3-byte length + 1-byte seq + protocol version (0x0a)
            proto_version = data[4]
            if proto_version != 0x0A:
                return None

            # Server version is null-terminated string starting at byte 5
            null_pos = data.find(b"\x00", 5)
            if null_pos == -1:
                return None

            version = data[5:null_pos].decode("utf-8", errors="replace")

            # Check for TiDB in version string
            if "TiDB" not in version and "tidb" not in version.lower():
                return None

            metadata: dict = {
                "protocol_version": proto_version,
                "product": "TiDB",
                "mysql_version_string": version,
            }

            return ServiceIdentity(
                service="tidb",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
