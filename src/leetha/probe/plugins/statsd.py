"""StatsD probe plugin — send management command and check for stats response."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class StatsDProbePlugin(ServiceProbe):
    name = "statsd"
    protocol = "tcp"
    default_ports = [8126]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # StatsD TCP management interface (typically on conn.port 8126)
            # Send "stats\n" to request internal statistics
            conn.write(b"stats\n")
            data = conn.read(8192)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            lower = response.lower()

            # Look for StatsD-specific markers in management response
            # Common fields: uptime, messages.*, counters, timers, gauges
            statsd_markers = [
                "uptime",
                "messages.",
                "counters",
                "timers",
                "gauges",
                "end",
            ]

            matches = sum(1 for marker in statsd_markers if marker in lower)
            if matches < 2:
                return None

            metadata: dict = {}
            version = None

            # Parse key-value stats
            for line in response.splitlines():
                line = line.strip()
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip()
                    val = val.strip()
                    if key == "version":
                        version = val
                        metadata["version"] = val
                    elif key == "uptime":
                        metadata["uptime"] = val

            metadata["stat_markers_found"] = matches

            return ServiceIdentity(
                service="statsd",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
