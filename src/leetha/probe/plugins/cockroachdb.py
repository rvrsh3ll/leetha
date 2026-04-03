"""CockroachDB probe plugin — PostgreSQL wire protocol with CockroachDB detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CockroachDBProbePlugin(ServiceProbe):
    name = "cockroachdb"
    protocol = "tcp"
    default_ports = [26257, 26258]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send PostgreSQL SSLRequest (same as PostgreSQL plugin)
            ssl_request = struct.pack(">II", 8, 80877103)
            conn.write(ssl_request)
            resp = conn.read(1)
            if not resp:
                return None

            # CockroachDB responds with 'N' (no SSL) or 'S' (SSL)
            if resp not in (b"N", b"S"):
                return None

            tls = resp == b"S"
            metadata: dict = {"ssl_supported": tls, "wire_protocol": "postgresql"}

            # Now send a StartupMessage to get server info
            # Build startup message with user=root, database=defaultdb
            params = b"user\x00root\x00database\x00defaultdb\x00\x00"
            # Version 3.0
            startup = struct.pack(">I", 0x00030000) + params
            length = struct.pack(">I", len(startup) + 4)
            conn.write(length + startup)

            # Read response - look for AuthenticationOk or ErrorResponse
            data = conn.read(4096)
            if not data or len(data) < 5:
                return ServiceIdentity(
                    service="cockroachdb",
                    certainty=80,
                    tls=tls,
                    metadata=metadata,
                )

            # Parse PostgreSQL messages to find server version
            version = None
            offset = 0
            while offset + 5 <= len(data):
                msg_type = chr(data[offset])
                msg_len = struct.unpack(">I", data[offset + 1:offset + 5])[0]
                msg_body = data[offset + 5:offset + 1 + msg_len]

                if msg_type == "S":  # ParameterStatus
                    parts = msg_body.split(b"\x00")
                    if len(parts) >= 2:
                        key = parts[0].decode("utf-8", errors="replace")
                        val = parts[1].decode("utf-8", errors="replace")
                        if key == "server_version":
                            version = val
                            metadata["server_version"] = val
                        elif key == "crdb_version":
                            metadata["crdb_version"] = val
                        if "cockroach" in val.lower() or "crdb" in key.lower():
                            metadata["confirmed_cockroachdb"] = True

                offset += 1 + msg_len

            return ServiceIdentity(
                service="cockroachdb",
                certainty=80,
                version=version,
                tls=tls,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
