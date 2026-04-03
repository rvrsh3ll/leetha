"""TeamViewer probe plugin — handshake detection for TeamViewer remote access."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TeamViewerProbePlugin(ServiceProbe):
    name = "teamviewer"
    protocol = "tcp"
    default_ports = [5938]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send TeamViewer handshake bytes
            handshake = b"\x17\x24\x0a\x20"
            conn.write(handshake)
            data = conn.read(1024)
            if not data or len(data) < 2:
                return None

            # Check for TeamViewer response signature
            if data[0:2] != b"\x17\x24":
                return None

            metadata: dict = {
                "response_length": len(data),
            }

            # Parse additional bytes if available
            if len(data) >= 4:
                metadata["response_prefix"] = data[:4].hex()

            return ServiceIdentity(
                service="teamviewer",
                certainty=80,
                version=None,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
