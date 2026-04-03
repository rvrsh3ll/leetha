"""Slurm Workload Manager probe plugin — sends Slurm RPC request, detects protocol version."""
from __future__ import annotations

import struct
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SlurmProbePlugin(ServiceProbe):
    name = "slurm"
    protocol = "tcp"
    default_ports = [6817, 6818]

    # Slurm protocol magic / header constants
    _SLURM_MAGIC = 0x9669
    _SLURM_PROTOCOL_VERSION = 0x2600  # protocol version 38.0

    def _build_request(self) -> bytes:
        """Build a minimal Slurm RPC request header (ping)."""
        # Slurm wire protocol: magic(2) + version(2) + msg_type(2) + body_len(4)
        msg_type = 8001  # REQUEST_PING
        body = b""
        header = struct.pack(">HHhI", self._SLURM_MAGIC, self._SLURM_PROTOCOL_VERSION,
                             msg_type, len(body))
        return header + body

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(self._build_request())
            data = conn.read(4096)
            if not data or len(data) < 10:
                return None

            magic = struct.unpack(">H", data[0:2])[0]
            if magic != self._SLURM_MAGIC:
                return None

            version = struct.unpack(">H", data[2:4])[0]
            msg_type = struct.unpack(">h", data[4:6])[0]

            metadata: dict = {
                "protocol_version": version,
                "msg_type": msg_type,
            }

            version_str = f"{version >> 8}.{version & 0xFF}"

            return ServiceIdentity(
                service="slurm",
                certainty=90,
                version=version_str,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
