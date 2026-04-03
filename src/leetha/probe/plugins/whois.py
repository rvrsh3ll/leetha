"""WHOIS protocol probe plugin — detect whois services."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class WHOISProbePlugin(ServiceProbe):
    name = "whois"
    protocol = "tcp"
    default_ports = [43]

    _WHOIS_RE = re.compile(
        r"(?:domain\s*name|registr(?:ar|y)|whois\s*server|name\s*server|"
        r"creation\s*date|updated?\s*date|expir(?:ation|y)\s*date|"
        r"refer|%\s*whois|%\s*this\s*is|netrange|orgname|netname)",
        re.IGNORECASE,
    )
    _REGISTRAR_RE = re.compile(r"(?:Registrar|Registry):\s*(.+)", re.IGNORECASE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send a common test query
            conn.write(b"example.com\r\n")

            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace").strip()
            if not text:
                return None

            # Look for whois response patterns
            matches = self._WHOIS_RE.findall(text)
            if not matches:
                return None

            metadata: dict = {
                "whois_fields": len(matches),
            }

            # Try to extract registrar info
            reg_match = self._REGISTRAR_RE.search(text)
            if reg_match:
                metadata["registrar"] = reg_match.group(1).strip()

            banner = text[:512]

            return ServiceIdentity(
                service="whois",
                certainty=85,
                version=None,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
