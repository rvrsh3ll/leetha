"""Tinc VPN probe plugin — banner grab for tinc daemon identification."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TincProbePlugin(ServiceProbe):
    name = "tinc"
    protocol = "tcp"
    default_ports = [655]

    # Tinc sends "0 <name> <version>" on connection
    _BANNER_RE = re.compile(r"^0\s+(\S+)\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Tinc sends an ID line immediately upon connection
            data = conn.read(1024)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()

            # Check for tinc identification line: "0 <name> <version>"
            match = self._BANNER_RE.match(banner)
            if not match:
                return None

            node_name = match.group(1)
            protocol_version = match.group(2)

            metadata: dict = {
                "node_name": node_name,
                "protocol_version": protocol_version,
                "raw_banner": banner,
            }

            return ServiceIdentity(
                service="tinc",
                certainty=80,
                version=protocol_version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
