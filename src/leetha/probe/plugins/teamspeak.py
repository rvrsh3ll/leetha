"""TeamSpeak 3 ServerQuery probe plugin — banner detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TeamSpeakProbePlugin(ServiceProbe):
    name = "teamspeak"
    protocol = "tcp"
    default_ports = [10011]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # TeamSpeak 3 ServerQuery sends banner on connect
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")
            banner = text.strip()

            # Must start with "TS3" prefix
            if not text.startswith("TS3"):
                return None

            metadata = {}
            version = None

            # Parse the welcome message
            # Typical format:
            # TS3
            # Welcome to the TeamSpeak 3 ServerQuery interface...
            # ...
            lines = text.split("\n")
            if len(lines) > 1:
                welcome_line = lines[1].strip()
                metadata["welcome"] = welcome_line

                # Extract version from welcome message
                ver_match = re.search(
                    r"TeamSpeak\s+3[^,]*,?\s*(?:build|version)[:\s]+(\S+)",
                    welcome_line,
                    re.IGNORECASE,
                )
                if ver_match:
                    version = ver_match.group(1)

            # Look for platform info
            for line in lines:
                if "platform" in line.lower():
                    plat_match = re.search(r"platform[:\s]+(\S+)", line, re.IGNORECASE)
                    if plat_match:
                        metadata["platform"] = plat_match.group(1)

            return ServiceIdentity(
                service="teamspeak",
                certainty=90,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
