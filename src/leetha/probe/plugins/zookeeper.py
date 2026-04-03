"""ZooKeeper probe plugin — four letter command (srvr) for ZooKeeper detection."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ZooKeeperProbePlugin(ServiceProbe):
    name = "zookeeper"
    protocol = "tcp"
    default_ports = [2181]

    _VERSION_RE = re.compile(r"Zookeeper version:\s*([^\n,]+)")
    _LATENCY_RE = re.compile(r"Latency min/avg/max:\s*(\d+)/(\d+)/(\d+)")
    _CONNECTIONS_RE = re.compile(r"Connections:\s*(\d+)")
    _OUTSTANDING_RE = re.compile(r"Outstanding:\s*(\d+)")
    _MODE_RE = re.compile(r"Mode:\s*(\w+)")
    _NODE_COUNT_RE = re.compile(r"Node count:\s*(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send "srvr" four letter command
            conn.write(b"srvr\n")
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for ZooKeeper markers
            has_version = "Zookeeper version:" in response
            has_latency = "Latency min/avg/max:" in response

            if not (has_version or has_latency):
                return None

            metadata: dict = {}
            version = None

            version_match = self._VERSION_RE.search(response)
            if version_match:
                version = version_match.group(1).strip()

            latency_match = self._LATENCY_RE.search(response)
            if latency_match:
                metadata["latency_min"] = int(latency_match.group(1))
                metadata["latency_avg"] = int(latency_match.group(2))
                metadata["latency_max"] = int(latency_match.group(3))

            connections_match = self._CONNECTIONS_RE.search(response)
            if connections_match:
                metadata["connections"] = int(connections_match.group(1))

            outstanding_match = self._OUTSTANDING_RE.search(response)
            if outstanding_match:
                metadata["outstanding"] = int(outstanding_match.group(1))

            mode_match = self._MODE_RE.search(response)
            if mode_match:
                metadata["mode"] = mode_match.group(1)

            node_count_match = self._NODE_COUNT_RE.search(response)
            if node_count_match:
                metadata["node_count"] = int(node_count_match.group(1))

            return ServiceIdentity(
                service="zookeeper",
                certainty=90,
                version=version,
                metadata=metadata,
                banner=response[:512],
            )
        except (socket.timeout, OSError):
            return None
