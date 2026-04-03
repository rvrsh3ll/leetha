"""POP3 probe plugin — banner grab."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class POP3ProbePlugin(ServiceProbe):
    name = "pop3"
    protocol = "tcp"
    default_ports = [110, 995]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None
            banner = data.decode("utf-8", errors="replace").strip()
            if not banner.startswith("+OK"):
                return None
            return ServiceIdentity(service="pop3", banner=banner, certainty=90)
        except (socket.timeout, OSError):
            return None
