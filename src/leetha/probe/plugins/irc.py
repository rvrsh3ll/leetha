"""IRC probe plugin — server registration response detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IRCProbePlugin(ServiceProbe):
    name = "irc"
    protocol = "tcp"
    default_ports = [6667, 6697]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send NICK and USER commands to trigger server response
            conn.write(b"NICK leetha\r\nUSER leetha 0 * :probe\r\n")
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")
            banner = text.strip()

            # IRC servers respond with numeric replies or NOTICE
            # Look for patterns like ":server 001 ...", ":server NOTICE ..."
            # or "NOTICE AUTH :***"
            is_irc = False
            metadata = {}
            version = None

            # Check for numeric reply (e.g. 001 RPL_WELCOME)
            numeric_match = re.search(
                r":(\S+)\s+(\d{3})\s+", text
            )
            if numeric_match:
                is_irc = True
                metadata["server_host"] = numeric_match.group(1)
                metadata["numeric_reply"] = int(numeric_match.group(2))

            # Check for NOTICE pattern
            if not is_irc:
                notice_match = re.search(
                    r":([\S]+)\s+NOTICE\s+", text, re.IGNORECASE
                )
                if notice_match:
                    is_irc = True
                    metadata["server_host"] = notice_match.group(1)

            # Check for bare NOTICE (e.g. "NOTICE AUTH :***")
            if not is_irc:
                bare_notice = re.match(r"NOTICE\s+", text, re.IGNORECASE)
                if bare_notice:
                    is_irc = True

            # Check for ERROR response (still indicates IRC)
            if not is_irc:
                if text.startswith("ERROR ") or text.startswith(":") and " ERROR " in text:
                    is_irc = True
                    metadata["error"] = True

            # Check for PING (some servers send PING before anything)
            if not is_irc:
                if text.startswith("PING "):
                    is_irc = True
                    metadata["ping_first"] = True

            if not is_irc:
                return None

            # Try to extract version from RPL_YOURHOST (002) or similar
            ver_match = re.search(
                r"running\s+(?:version\s+)?(\S+)", text, re.IGNORECASE
            )
            if ver_match:
                version = ver_match.group(1)

            # Try server software detection
            for sw in ("UnrealIRCd", "InspIRCd", "ircd-hybrid", "charybdis", "ngircd"):
                if sw.lower() in text.lower():
                    metadata["software"] = sw
                    break

            return ServiceIdentity(
                service="irc",
                certainty=85,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
