"""PBS/Torque batch scheduler probe plugin — sends PBS batch request, detects PBS server."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PBSProbePlugin(ServiceProbe):
    name = "pbs"
    protocol = "tcp"
    default_ports = [15001]

    _VERSION_RE = re.compile(r"PBS[_ ](?:Pro|Server|Torque)[/ ]*([\d.]+)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send a PBS batch status request (QueueJob request type 0)
            # PBS wire: +2 header "PBS\n" then operation
            conn.write(b"PBS\n")
            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            if "PBS" not in response.upper():
                return None

            metadata: dict = {"raw_response": response[:256]}
            version = None

            m = self._VERSION_RE.search(response)
            if m:
                version = m.group(1)

            if "Torque" in response or "torque" in response:
                metadata["variant"] = "Torque"
            elif "PBS Pro" in response or "PBSPro" in response:
                metadata["variant"] = "PBS Pro"
            else:
                metadata["variant"] = "PBS"

            return ServiceIdentity(
                service="pbs",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
