"""NNTP probe plugin — detect Usenet NNTP servers via banner."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NNTPProbePlugin(ServiceProbe):
    name = "nntp"
    protocol = "tcp"
    default_ports = [119]

    _BANNER_RE = re.compile(r"^(200|201)\s+(.+)", re.DOTALL)
    _VERSION_RE = re.compile(r"(?:INN|InterNetNews|Diablo|DNews|Leafnode|tin)[\s\w.-]*?([\d]+(?:\.[\d]+)+)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # NNTP sends banner immediately upon connection
            data = conn.read(1024)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()
            match = self._BANNER_RE.match(banner)
            if not match:
                return None

            code = match.group(1)
            greeting = match.group(2).strip()
            metadata: dict = {
                "code": int(code),
                "posting_allowed": code == "200",
            }

            version = None
            ver_match = self._VERSION_RE.search(greeting)
            if ver_match:
                version = ver_match.group(0).strip()
                metadata["software"] = version

            return ServiceIdentity(
                service="nntp",
                certainty=90,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
