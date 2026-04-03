"""GPFS/Spectrum Scale probe plugin — sends cluster query, detects mmfsd response."""
from __future__ import annotations

import struct
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GPFSProbePlugin(ServiceProbe):
    name = "gpfs"
    protocol = "tcp"
    default_ports = [1191]

    # GPFS mmfsd protocol magic
    _GPFS_MAGIC = 0x47504653  # "GPFS"

    def _build_query(self) -> bytes:
        """Build a minimal GPFS mmfsd cluster status query."""
        # GPFS wire: magic(4) + version(4) + msg_type(4) + payload_len(4)
        magic = self._GPFS_MAGIC
        version = 1
        msg_type = 1  # STATUS_QUERY
        payload = b""
        header = struct.pack(">IIII", magic, version, msg_type, len(payload))
        return header + payload

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(self._build_query())
            data = conn.read(4096)
            if not data or len(data) < 16:
                return None

            magic = struct.unpack(">I", data[0:4])[0]
            if magic != self._GPFS_MAGIC:
                return None

            version = struct.unpack(">I", data[4:8])[0]
            msg_type = struct.unpack(">I", data[8:12])[0]
            payload_len = struct.unpack(">I", data[12:16])[0]

            metadata: dict = {
                "protocol_version": version,
                "msg_type": msg_type,
                "payload_len": payload_len,
            }

            version_str = str(version)

            # Try to extract cluster name from payload
            if payload_len > 0 and len(data) > 16:
                payload = data[16:16 + payload_len]
                try:
                    text = payload.decode("utf-8", errors="replace")
                    if text.strip():
                        metadata["cluster_info"] = text.strip()[:128]
                except Exception:
                    pass

            return ServiceIdentity(
                service="gpfs",
                certainty=85,
                version=version_str,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
