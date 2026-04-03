"""RSH (Remote Shell) probe plugin — detect rsh service."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RSHProbePlugin(ServiceProbe):
    name = "rsh"
    protocol = "tcp"
    default_ports = [514]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # RSH protocol:
            # Client sends: port\0client_user\0server_user\0command\0
            # Server responds with: \x00 on success, or error text
            # Port "0" means no stderr
            rsh_request = b"0\x00probe\x00probe\x00id\x00"
            conn.write(rsh_request)

            data = conn.read(1024)
            if not data:
                return None

            metadata: dict = {}

            # RSH success: first byte is null
            if data[0:1] == b"\x00":
                metadata["accepted"] = True
                if len(data) > 1:
                    output = data[1:].decode("utf-8", errors="replace").strip()
                    if output:
                        metadata["output"] = output[:256]
                return ServiceIdentity(
                    service="rsh",
                    certainty=80,
                    version=None,
                    banner=metadata.get("output"),
                    metadata=metadata,
                )

            # RSH error: first byte is \x01 followed by error text
            if data[0:1] == b"\x01":
                error_text = data[1:].decode("utf-8", errors="replace").strip()
                metadata["error"] = error_text[:256]
                return ServiceIdentity(
                    service="rsh",
                    certainty=75,
                    version=None,
                    banner=error_text[:256],
                    metadata=metadata,
                )

            # Some rsh daemons respond with plain text errors
            text = data.decode("utf-8", errors="replace").strip()
            rsh_keywords = ("permission denied", "connection refused",
                            "not allowed", "authentication", "rshd",
                            "remshd", "login incorrect")
            if any(kw in text.lower() for kw in rsh_keywords):
                metadata["banner"] = text[:256]
                return ServiceIdentity(
                    service="rsh",
                    certainty=65,
                    version=None,
                    banner=text[:256],
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError):
            return None
