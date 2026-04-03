"""MPD probe plugin — Music Player Daemon banner detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MPDProbePlugin(ServiceProbe):
    name = "mpd"
    protocol = "tcp"
    default_ports = [6600]

    _BANNER_RE = re.compile(r"^OK MPD\s+([\d.]+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()

            match = self._BANNER_RE.match(banner)
            if not match:
                return None

            version = match.group(1)
            return ServiceIdentity(
                service="mpd",
                certainty=95,
                version=version,
                metadata={"mpd_version": version},
                banner=banner,
            )
        except (socket.timeout, OSError):
            return None
