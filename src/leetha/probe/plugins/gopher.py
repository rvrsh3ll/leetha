"""Gopher protocol probe plugin — detect gopher menu responses."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GopherProbePlugin(ServiceProbe):
    name = "gopher"
    protocol = "tcp"
    default_ports = [70]

    # Gopher item type characters (first char of each line)
    _VALID_TYPES = set("0123456789+TgiIhsp")
    _LINE_RE = re.compile(r"^([0-9iIhgsTp+])(.*?)\t(.*?)\t(.*?)\t(\d+)")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send empty selector (CRLF) to get root menu
            conn.write(b"\r\n")

            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")
            lines = text.split("\n")

            metadata: dict = {}
            gopher_lines = 0
            item_types: set[str] = set()

            for line in lines:
                line = line.rstrip("\r")
                if not line or line == ".":
                    continue
                # Check if line matches gopher menu format:
                # type_char + display_string \t selector \t conn.host \t conn.port
                if line[0:1] in self._VALID_TYPES and "\t" in line:
                    gopher_lines += 1
                    item_types.add(line[0])
                match = self._LINE_RE.match(line)
                if match:
                    gopher_lines += 1
                    item_types.add(match.group(1))

            # Deduplicate count (both checks may match same line)
            if gopher_lines == 0:
                return None

            # Need at least one gopher-formatted line
            metadata["gopher_lines"] = gopher_lines
            metadata["item_types"] = sorted(item_types)

            return ServiceIdentity(
                service="gopher",
                certainty=85,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
