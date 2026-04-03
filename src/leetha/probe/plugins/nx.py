"""NX probe plugin — banner grab for NX/NoMachine remote desktop."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NXProbePlugin(ServiceProbe):
    name = "nx"
    protocol = "tcp"
    default_ports = [4000]

    _VERSION_RE = re.compile(r"NXSERVER\s*-\s*Version\s+([\d.]+(?:-[\w.]+)?)", re.IGNORECASE)
    _NX_RE = re.compile(r"NX>", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()

            # Check for NX> prompt or NXSERVER identifier
            if not (self._NX_RE.search(banner) or "NXSERVER" in banner.upper()):
                return None

            metadata: dict = {"raw_banner": banner[:512]}
            version = None

            # Try to extract version
            vm = self._VERSION_RE.search(banner)
            if vm:
                version = vm.group(1)

            return ServiceIdentity(
                service="nx",
                certainty=85,
                version=version,
                banner=banner[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
