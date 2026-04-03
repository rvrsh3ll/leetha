"""MSSQL probe plugin — TDS pre-login."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MSSQLProbePlugin(ServiceProbe):
    name = "mssql"
    protocol = "tcp"
    default_ports = [1433]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # TDS 7.0 Pre-Login packet
            prelogin = (
                b"\x12\x01\x00\x2f\x00\x00\x01\x00"  # TDS header
                b"\x00\x00\x15\x00\x06"  # VERSION token
                b"\x01\x00\x1b\x00\x01"  # ENCRYPTION token
                b"\x02\x00\x1c\x00\x01"  # INSTOPT token
                b"\x03\x00\x1d\x00\x04"  # THREADID token
                b"\xff"                   # Terminator
                b"\x0e\x00\x04\x00\x00\x00"  # Version data
                b"\x00"                   # Encryption
                b"\x00"                   # Instance
                b"\x00\x00\x00\x00"       # ThreadID
            )
            conn.write(prelogin)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None
            # TDS response type 0x04 = Tabular Result
            if data[0] == 0x04:
                metadata = {}
                # Try to extract version from prelogin response
                if len(data) > 26:
                    try:
                        major = data[21]
                        minor = data[22]
                        metadata["version_major"] = major
                        metadata["version_minor"] = minor
                    except IndexError:
                        pass
                return ServiceIdentity(service="mssql", certainty=90, metadata=metadata)
            return None
        except (socket.timeout, OSError, struct.error):
            return None
