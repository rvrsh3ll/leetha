"""ManageSieve probe plugin — Sieve script management protocol."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ManageSieveProbePlugin(ServiceProbe):
    name = "managesieve"
    protocol = "tcp"
    default_ports = [4190]

    _IMPL_RE = re.compile(r'"IMPLEMENTATION"\s+"([^"]+)"', re.IGNORECASE)
    _SASL_RE = re.compile(r'"SASL"\s+"([^"]+)"', re.IGNORECASE)
    _SIEVE_RE = re.compile(r'"SIEVE"\s+"([^"]+)"', re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(4096)
            if not data:
                return None

            banner = data.decode("utf-8", errors="replace")

            # ManageSieve capabilities start with quoted keywords
            if '"IMPLEMENTATION"' not in banner and '"SASL"' not in banner:
                return None

            metadata: dict = {}
            version = None

            impl = self._IMPL_RE.search(banner)
            if impl:
                version = impl.group(1)
                metadata["implementation"] = impl.group(1)

            sasl = self._SASL_RE.search(banner)
            if sasl:
                metadata["sasl_mechanisms"] = sasl.group(1)

            sieve = self._SIEVE_RE.search(banner)
            if sieve:
                metadata["sieve_extensions"] = sieve.group(1)

            return ServiceIdentity(
                service="managesieve",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=banner[:512],
            )
        except (socket.timeout, OSError):
            return None
