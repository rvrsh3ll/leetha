"""SSH probe plugin — banner grab and version extraction."""

from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SSHProbePlugin(ServiceProbe):
    name = "ssh"
    protocol = "tcp"
    default_ports = [22, 2222, 22222]

    _BANNER_RE = re.compile(r"^SSH-[\d.]+-(\S+)")

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

            banner_lower = banner.lower()
            if "ubuntu" in banner_lower:
                metadata["os_hint"] = "Ubuntu"
            elif "debian" in banner_lower:
                metadata["os_hint"] = "Debian"
            elif "freebsd" in banner_lower:
                metadata["os_hint"] = "FreeBSD"

            return ServiceIdentity(
                service="ssh",
                version=version,
                banner=banner,
                metadata=metadata,
                certainty=95,
            )
        except (socket.timeout, OSError):
            return None
