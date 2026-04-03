"""HTCondor probe plugin — sends ClassAd query, detects HTCondor collector response."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CondorProbePlugin(ServiceProbe):
    name = "condor"
    protocol = "tcp"
    default_ports = [9618]

    _VERSION_RE = re.compile(r'CondorVersion\s*=\s*"([^"]+)"')
    _PLATFORM_RE = re.compile(r'CondorPlatform\s*=\s*"([^"]+)"')

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send a minimal ClassAd collector query
            # HTCondor wire: command(4 bytes LE) + length(4 bytes LE) + payload
            # Command 60011 = QUERY_ANY_ADS
            query = b"[MyType=\"Query\";TargetType=\"Any\";Requirements=true;]\n"
            conn.write(query)
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # HTCondor ClassAd format uses key = value pairs
            if "CondorVersion" not in response and "MyType" not in response:
                return None

            metadata: dict = {}
            version = None

            m = self._VERSION_RE.search(response)
            if m:
                version = m.group(1)

            m = self._PLATFORM_RE.search(response)
            if m:
                metadata["platform"] = m.group(1)

            if "MyType" in response:
                my_type_match = re.search(r'MyType\s*=\s*"([^"]+)"', response)
                if my_type_match:
                    metadata["ad_type"] = my_type_match.group(1)

            return ServiceIdentity(
                service="condor",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
