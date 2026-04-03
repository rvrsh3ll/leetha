"""SANE probe plugin — Scanner Access Now Easy network protocol."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SANEProbePlugin(ServiceProbe):
    name = "sane"
    protocol = "tcp"
    default_ports = [6566]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # SANE_NET_INIT request
            # RPC code for SANE_NET_INIT = 0
            # Version code: SANE version 1.0.3 encoded as
            # (major << 24) | (minor << 16) | build
            version_code = (1 << 24) | (0 << 16) | 3  # 1.0.3
            username = b"leetha\x00"

            request = struct.pack(">I", 0)  # SANE_NET_INIT
            request += struct.pack(">I", version_code)
            # String: length-prefixed (including null terminator)
            request += struct.pack(">I", len(username))
            request += username

            conn.write(request)
            data = conn.read(4096)

            if not data or len(data) < 8:
                return None

            # Parse SANE_NET_INIT response
            # Status word (4 bytes) + version code (4 bytes)
            status = struct.unpack(">I", data[0:4])[0]
            resp_version = struct.unpack(">I", data[4:8])[0]

            # Extract version components
            major = (resp_version >> 24) & 0xFF
            minor = (resp_version >> 16) & 0xFF
            build = resp_version & 0xFFFF

            # Sanity check: major version should be reasonable (0-10)
            if major > 10:
                return None

            metadata: dict = {
                "status": status,
                "sane_version": f"{major}.{minor}.{build}",
                "version_code": resp_version,
            }

            version = f"SANE {major}.{minor}.{build}"

            return ServiceIdentity(
                service="sane",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
