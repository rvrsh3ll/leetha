"""Redis probe plugin — PING command."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RedisProbePlugin(ServiceProbe):
    name = "redis"
    protocol = "tcp"
    default_ports = [6379]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(b"*1\r\n$4\r\nPING\r\n")
            data = conn.read(1024)
            if not data:
                return None
            response = data.decode("utf-8", errors="replace").strip()
            if response == "+PONG":
                # Try INFO for version
                conn.write(b"*1\r\n$4\r\nINFO\r\n")
                info = conn.read(4096).decode("utf-8", errors="replace")
                version = None
                for line in info.split("\r\n"):
                    if line.startswith("redis_version:"):
                        version = line.split(":")[1]
                        break
                return ServiceIdentity(service="redis", version=version, certainty=95, metadata={"auth_required": False})
            elif "-NOAUTH" in response or "-ERR" in response:
                return ServiceIdentity(service="redis", certainty=85, metadata={"auth_required": True})
            return None
        except (socket.timeout, OSError):
            return None
