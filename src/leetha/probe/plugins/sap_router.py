"""SAP Router probe plugin — NI protocol info request."""
from __future__ import annotations
import re
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SAPRouterProbePlugin(ServiceProbe):
    name = "sap_router"
    protocol = "tcp"
    default_ports = [3299]

    _VERSION_RE = re.compile(r"SAP\s*(?:Network\s*Interface\s*)?Router\s*(\d+\.\d+)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build NI (Network Interface) route info request
            # NI header: length(4, big-endian) + payload
            # SAP Router admin info request: "NI_PING\x00" or route info
            ni_payload = b"NI_PING\x00"
            ni_header = struct.pack(">I", len(ni_payload))
            conn.write(ni_header + ni_payload)

            data = conn.read(4096)
            if not data or len(data) < 4:
                return None

            metadata: dict = {}
            version = None

            # Check for NI response header
            if len(data) >= 4:
                resp_len = struct.unpack(">I", data[0:4])[0]
                metadata["response_length"] = resp_len

            # Decode response body
            body = data[4:] if len(data) > 4 else data
            text = body.decode("utf-8", errors="replace")

            # Look for SAP Router indicators
            if "NI_PONG" in text:
                metadata["pong"] = True
            elif "SAP" in text.upper() and ("ROUTER" in text.upper() or "NI" in text.upper()):
                metadata["sap_identified"] = True
            else:
                # Check for NI error response which still identifies the service
                if resp_len < 4 or b"NI" not in data:
                    return None

            ver_match = self._VERSION_RE.search(text)
            if ver_match:
                version = ver_match.group(1)

            return ServiceIdentity(
                service="sap_router",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
