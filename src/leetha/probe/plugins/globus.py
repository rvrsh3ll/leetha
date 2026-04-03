"""Globus GridFTP control probe plugin — detects GridFTP banner."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GlobusProbePlugin(ServiceProbe):
    name = "globus"
    protocol = "tcp"
    default_ports = [2811]

    _BANNER_RE = re.compile(r"^220[- ](.+)", re.MULTILINE)
    _VERSION_RE = re.compile(r"(?:GridFTP|globus)[\w\s-]*?([\d]+(?:\.[\d]+)+)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(4096)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()

            # Must start with 220 (FTP ready) and contain GridFTP or globus
            m = self._BANNER_RE.search(banner)
            if not m:
                return None

            banner_text = m.group(1)
            lower = banner_text.lower()
            if "gridftp" not in lower and "globus" not in lower:
                return None

            metadata: dict = {"banner_text": banner_text}
            version = None

            vm = self._VERSION_RE.search(banner)
            if vm:
                version = vm.group(1)

            return ServiceIdentity(
                service="globus",
                certainty=90,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
