"""VNC probe plugin — RFB protocol version handshake."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class VNCProbePlugin(ServiceProbe):
    name = "vnc"
    protocol = "tcp"
    default_ports = [5900, 5901, 5902, 5903]

    _RFB_RE = re.compile(r"^RFB (\d{3}\.\d{3})")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None
            banner = data.decode("utf-8", errors="replace").strip()
            m = self._RFB_RE.match(banner)
            if not m:
                return None
            rfb_version = m.group(1)
            return ServiceIdentity(service="vnc", version=f"RFB {rfb_version}", banner=banner, certainty=95, metadata={"rfb_version": rfb_version})
        except (socket.timeout, OSError):
            return None
