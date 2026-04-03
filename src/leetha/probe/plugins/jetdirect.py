"""JetDirect probe plugin — HP JetDirect print server (PJL)."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class JetDirectProbePlugin(ServiceProbe):
    name = "jetdirect"
    protocol = "tcp"
    default_ports = [9100]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send PJL INFO STATUS request
            # UEL (Universal Exit Language) + PJL command
            request = b"\x1b%-12345X@PJL INFO STATUS\r\n\x1b%-12345X"

            conn.write(request)
            data = conn.read(4096)

            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for PJL response markers
            if "@PJL" not in response and "INFO" not in response:
                return None

            metadata: dict = {}
            version = None

            # Parse PJL response lines
            lines = response.strip().split("\n")
            for line in lines:
                line = line.strip()
                if "=" in line:
                    key, _, val = line.partition("=")
                    key = key.strip().lower()
                    val = val.strip()
                    if key == "code":
                        metadata["status_code"] = val
                    elif key == "online":
                        metadata["online"] = val.upper() == "TRUE"
                    elif key == "display" or key == "name":
                        metadata["display"] = val
                        version = val

            return ServiceIdentity(
                service="jetdirect",
                certainty=85,
                version=version,
                banner=response[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
