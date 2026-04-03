"""SSDP probe plugin — UPnP Simple Service Discovery Protocol."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SSDPProbePlugin(ServiceProbe):
    name = "ssdp"
    protocol = "udp"
    default_ports = [1900]

    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                b"M-SEARCH * HTTP/1.1\r\n"
                b"HOST: 239.255.255.250:1900\r\n"
                b"MAN: \"ssdp:discover\"\r\n"
                b"MX: 1\r\n"
                b"ST: ssdp:all\r\n"
                b"\r\n"
            )

            conn.write(request)
            data = conn.read(4096)

            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            # Check for HTTP/1.1 200 OK response
            if not response.startswith("HTTP/1.1 200"):
                return None

            headers = dict(self._HEADER_RE.findall(response))
            metadata: dict = {}
            version = None

            server = headers.get("SERVER") or headers.get("Server") or headers.get("server")
            if server:
                metadata["server"] = server
                version = server

            st = headers.get("ST") or headers.get("St") or headers.get("st")
            if st:
                metadata["search_target"] = st

            usn = headers.get("USN") or headers.get("Usn") or headers.get("usn")
            if usn:
                metadata["usn"] = usn

            location = headers.get("LOCATION") or headers.get("Location") or headers.get("location")
            if location:
                metadata["location"] = location

            return ServiceIdentity(
                service="ssdp",
                certainty=78,
                version=version,
                banner=response[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
