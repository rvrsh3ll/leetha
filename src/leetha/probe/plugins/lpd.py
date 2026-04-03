"""LPD probe plugin — Line Printer Daemon protocol."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LPDProbePlugin(ServiceProbe):
    name = "lpd"
    protocol = "tcp"
    default_ports = [515]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send LPD queue status request
            # Command 0x04 = "Send queue state (long)"
            # Followed by queue name + newline
            request = b"\x04lp\n"

            conn.write(request)
            data = conn.read(4096)

            if data is None:
                return None

            # Any response (even an error) confirms LPD is listening
            # LPD can send back status text or a single error byte
            metadata: dict = {"response_length": len(data)}
            banner = None

            if data:
                response = data.decode("utf-8", errors="replace")
                banner = response[:512]
                # Look for common LPD response patterns
                lower = response.lower()
                if "printer" in lower or "queue" in lower or "job" in lower:
                    metadata["has_status_info"] = True
                if "not available" in lower or "error" in lower or "refused" in lower:
                    metadata["error"] = True

            return ServiceIdentity(
                service="lpd",
                certainty=75,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
