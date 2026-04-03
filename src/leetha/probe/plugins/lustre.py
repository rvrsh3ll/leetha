"""Lustre filesystem probe plugin — sends LNET ping, detects Lustre LNET response."""
from __future__ import annotations

import struct
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LustreProbePlugin(ServiceProbe):
    name = "lustre"
    protocol = "tcp"
    default_ports = [988]

    # LNET magic numbers
    _LNET_MAGIC = 0x45726963  # "Eric" — LNET wire protocol magic
    _LNET_PING_MAGIC = 0x70696E67  # "ping"

    def _build_lnet_ping(self) -> bytes:
        """Build a minimal LNET ping request."""
        # LNET header: magic(4) + type(4) + src_nid(8) + dest_nid(8) + payload_len(4)
        magic = self._LNET_MAGIC
        msg_type = 4  # LNET_MSG_GET (ping)
        src_nid = struct.pack(">II", 0, 0)  # local NID placeholder
        dest_nid = struct.pack(">II", 0, 0)  # dest NID placeholder
        payload = struct.pack(">I", self._LNET_PING_MAGIC)
        payload_len = len(payload)
        header = struct.pack(">II", magic, msg_type) + src_nid + dest_nid + struct.pack(">I", payload_len)
        return header + payload

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(self._build_lnet_ping())
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            magic = struct.unpack(">I", data[0:4])[0]
            if magic != self._LNET_MAGIC:
                return None

            msg_type = struct.unpack(">I", data[4:8])[0]

            metadata: dict = {
                "msg_type": msg_type,
            }

            # Try to parse NID info
            if len(data) >= 24:
                src_addr = struct.unpack(">I", data[8:12])[0]
                src_net = struct.unpack(">I", data[12:16])[0]
                metadata["src_nid_addr"] = src_addr
                metadata["src_nid_net"] = src_net

            return ServiceIdentity(
                service="lustre",
                certainty=90,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
