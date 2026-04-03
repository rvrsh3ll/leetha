"""Perforce (Helix Core) probe plugin — server banner detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PerforceProbePlugin(ServiceProbe):
    name = "perforce"
    protocol = "tcp"
    default_ports = [1666]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send a minimal Perforce command to elicit a response
            # The simplest is to just connect and read the banner,
            # or send a "ping" equivalent
            conn.write(b"ping\n")
            data = conn.read(4096)
            if not data:
                return None

            # Perforce may also send data immediately on connect
            # Check the response for Perforce indicators
            text = data.decode("utf-8", errors="replace")
            banner = text.strip()

            is_perforce = False
            metadata = {}
            version = None

            # Check for Perforce/P4/Helix markers
            perforce_markers = [
                "Perforce", "P4D", "p4d", "Helix",
                "Server address", "server.id",
            ]
            for marker in perforce_markers:
                if marker in text:
                    is_perforce = True
                    break

            # Check for binary Perforce protocol response
            # Perforce RPC protocol starts with specific binary patterns
            if not is_perforce and len(data) >= 4:
                # Perforce binary protocol often has structured key-value data
                # with null-terminated strings
                if b"\x00" in data and (
                    b"server" in data.lower() or b"perforce" in data.lower()
                    or b"p4d" in data.lower()
                ):
                    is_perforce = True
                    metadata["binary_protocol"] = True

            if not is_perforce:
                return None

            # Try to extract version
            ver_match = re.search(
                r"(?:P4D|Perforce|Helix)[/\s]+(?:for\s+\S+\s+)?(\d+\.\d+[\.\d/]*)",
                text,
                re.IGNORECASE,
            )
            if ver_match:
                version = ver_match.group(1)

            # Try to extract server address
            addr_match = re.search(r"Server address:\s*(\S+)", text)
            if addr_match:
                metadata["server_address"] = addr_match.group(1)

            return ServiceIdentity(
                service="perforce",
                certainty=80,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
