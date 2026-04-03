"""LMTP probe plugin — Local Mail Transfer Protocol banner detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LMTPProbePlugin(ServiceProbe):
    name = "lmtp"
    protocol = "tcp"
    default_ports = [2003, 24]

    _BANNER_RE = re.compile(r"^220\s+(\S+)\s+(.*)", re.DOTALL)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(1024)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace").strip()

            if not banner.startswith("220"):
                return None

            # Must contain LMTP to distinguish from SMTP
            if "LMTP" not in banner:
                return None

            metadata: dict = {}
            version = None

            match = self._BANNER_RE.match(banner)
            if match:
                metadata["hostname"] = match.group(1)

            # Try to extract product info
            for pattern, name in [
                (r"Dovecot", "Dovecot"),
                (r"Postfix", "Postfix"),
                (r"Cyrus LMTP[d]?\s*([\d.]+)?", "Cyrus"),
            ]:
                vm = re.search(pattern, banner, re.IGNORECASE)
                if vm:
                    version = vm.group(0)
                    metadata["product"] = name
                    break

            return ServiceIdentity(
                service="lmtp",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=banner,
            )
        except (socket.timeout, OSError):
            return None
