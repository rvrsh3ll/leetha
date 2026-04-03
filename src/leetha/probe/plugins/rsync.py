"""Rsync probe plugin — banner grab for rsync daemon."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RsyncProbePlugin(ServiceProbe):
    name = "rsync"
    protocol = "tcp"
    default_ports = [873]

    _BANNER_RE = re.compile(r"^@RSYNCD:\s+([\d.]+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()
            m = self._BANNER_RE.match(banner)
            if not m:
                return None

            version = m.group(1)
            metadata: dict = {"raw_banner": banner}

            return ServiceIdentity(
                service="rsync",
                certainty=90,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
