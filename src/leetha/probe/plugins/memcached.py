"""Memcached probe plugin — stats command."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MemcachedProbePlugin(ServiceProbe):
    name = "memcached"
    protocol = "tcp"
    default_ports = [11211]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(b"version\r\n")
            data = conn.read(1024)
            if not data:
                return None
            response = data.decode("utf-8", errors="replace").strip()
            if response.startswith("VERSION "):
                version = response.split(" ", 1)[1]
                return ServiceIdentity(service="memcached", version=version, certainty=95)
            return None
        except (socket.timeout, OSError):
            return None
