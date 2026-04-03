"""SVN probe plugin — banner grab for Subversion svnserve daemon."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SVNProbePlugin(ServiceProbe):
    name = "svn"
    protocol = "tcp"
    default_ports = [3690]

    _SUCCESS_RE = re.compile(r"^\(\s*success\s*\(\s*(\d+)\s+(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(4096)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()

            if not banner.startswith("( success"):
                return None

            metadata: dict = {"raw_banner": banner[:512]}
            version = None

            m = self._SUCCESS_RE.match(banner)
            if m:
                version = m.group(1)
                metadata["min_version"] = int(m.group(1))
                metadata["max_version"] = int(m.group(2))

            return ServiceIdentity(
                service="svn",
                certainty=90,
                version=version,
                banner=banner[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
