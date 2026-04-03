"""NATS probe plugin — INFO line parsing."""
from __future__ import annotations
import json
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NATSProbePlugin(ServiceProbe):
    name = "nats"
    protocol = "tcp"
    default_ports = [4222, 6222, 8222]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            data = conn.read(4096)
            if not data:
                return None
            line = data.decode("utf-8", errors="replace").strip()
            if not line.startswith("INFO "):
                return None

            json_str = line[5:]  # strip "INFO " prefix
            metadata = {}
            version = None
            banner = line

            try:
                info = json.loads(json_str)
                if "server_id" in info:
                    metadata["server_id"] = info["server_id"]
                if "version" in info:
                    version = info["version"]
                if "max_payload" in info:
                    metadata["max_payload"] = info["max_payload"]
                if "proto" in info:
                    metadata["proto"] = info["proto"]
            except (json.JSONDecodeError, ValueError):
                pass

            return ServiceIdentity(
                service="nats",
                certainty=90,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
