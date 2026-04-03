"""IMAP probe plugin — banner grab."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IMAPProbePlugin(ServiceProbe):
    name = "imap"
    protocol = "tcp"
    default_ports = [143, 993]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None
            banner = data.decode("utf-8", errors="replace").strip()
            if "* OK" not in banner and "* PREAUTH" not in banner:
                return None
            return ServiceIdentity(service="imap", banner=banner, certainty=90)
        except (socket.timeout, OSError):
            return None
