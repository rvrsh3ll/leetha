"""SGE/Grid Engine probe plugin — sends commd request, detects Grid Engine response."""
from __future__ import annotations

import re
import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SGEProbePlugin(ServiceProbe):
    name = "sge"
    protocol = "tcp"
    default_ports = [6444]

    _VERSION_RE = re.compile(r"GE[/ ]([\d.]+)")

    def _build_commd_request(self) -> bytes:
        """Build a minimal SGE commd service request."""
        # SGE commd protocol: tag(4) + version(4) + request_type(4)
        tag = 0x47450001  # "GE" marker + version 1
        version = 1
        request_type = 0  # STATUS_REQUEST
        return struct.pack(">III", tag, version, request_type)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(self._build_commd_request())
            data = conn.read(4096)
            if not data:
                return None

            # Try binary response first
            if len(data) >= 12:
                tag = struct.unpack(">I", data[0:4])[0]
                if (tag >> 16) == 0x4745:  # "GE" in high bytes
                    resp_version = struct.unpack(">I", data[4:8])[0]
                    metadata: dict = {
                        "protocol_tag": hex(tag),
                        "protocol_version": resp_version,
                    }
                    return ServiceIdentity(
                        service="sge",
                        certainty=85,
                        version=str(resp_version),
                        metadata=metadata,
                    )

            # Try text response
            response = data.decode("utf-8", errors="replace")
            if "GE" in response or "Grid Engine" in response.replace("grid engine", "Grid Engine"):
                metadata = {"raw_response": response[:256]}
                version = None
                m = self._VERSION_RE.search(response)
                if m:
                    version = m.group(1)
                return ServiceIdentity(
                    service="sge",
                    certainty=75,
                    version=version,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError):
            return None
