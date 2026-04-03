"""BeeGFS parallel filesystem probe plugin — sends management protocol request, detects BeeGFS."""
from __future__ import annotations

import struct
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class BeeGFSProbePlugin(ServiceProbe):
    name = "beegfs"
    protocol = "tcp"
    default_ports = [8008]

    # BeeGFS protocol constants
    _BEEGFS_MAGIC = 0x42474653  # "BGFS"

    def _build_request(self) -> bytes:
        """Build a minimal BeeGFS management protocol heartbeat request."""
        # BeeGFS wire: magic(4) + msg_length(4) + msg_type(2) + padding(2)
        magic = self._BEEGFS_MAGIC
        msg_type = 1  # Heartbeat request
        padding = 0
        payload = b""
        msg_length = 4 + len(payload)  # msg_type(2) + padding(2) + payload
        header = struct.pack(">IIHh", magic, msg_length, msg_type, padding)
        return header + payload

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(self._build_request())
            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            magic = struct.unpack(">I", data[0:4])[0]
            if magic != self._BEEGFS_MAGIC:
                return None

            msg_length = struct.unpack(">I", data[4:8])[0]
            msg_type = struct.unpack(">H", data[8:10])[0]

            metadata: dict = {
                "msg_type": msg_type,
                "msg_length": msg_length,
            }

            # Try to parse node info from payload
            if len(data) > 12:
                payload = data[12:]
                try:
                    text = payload.decode("utf-8", errors="replace")
                    if text.strip():
                        metadata["node_info"] = text.strip()[:128]
                except Exception:
                    pass

            return ServiceIdentity(
                service="beegfs",
                certainty=85,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
