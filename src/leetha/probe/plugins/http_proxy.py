"""HTTP CONNECT proxy probe plugin — detects HTTP proxy servers."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class HTTPProxyProbePlugin(ServiceProbe):
    name = "http_proxy"
    protocol = "tcp"
    default_ports = [3128, 8080, 8888]

    _STATUS_RE = re.compile(r"^HTTP/[\d.]+\s+(\d+)\s*([^\r\n]*)", re.IGNORECASE)
    _HEADER_RE = re.compile(r"^([^\r\n:]+):\s*([^\r\n]+)", re.MULTILINE)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = (
                b"CONNECT example.com:443 HTTP/1.1\r\n"
                b"Host: example.com:443\r\n"
                b"\r\n"
            )

            conn.write(request)
            data = conn.read(4096)

            if not data:
                return None

            response = data.decode("utf-8", errors="replace")

            status_match = self._STATUS_RE.match(response)
            if not status_match:
                return None

            status_code = int(status_match.group(1))
            status_text = status_match.group(2).strip()

            # HTTP proxy responses: 200 (established), 403 (forbidden),
            # 407 (proxy auth required), 502 (bad gateway), etc.
            # Any valid HTTP response to CONNECT indicates a proxy
            headers = dict(self._HEADER_RE.findall(response))

            metadata: dict = {
                "status_code": status_code,
                "status_text": status_text,
            }
            version = None

            # Check for proxy-related headers
            proxy_agent = (
                headers.get("Proxy-Agent")
                or headers.get("proxy-agent")
                or headers.get("Via")
                or headers.get("via")
            )
            if proxy_agent:
                metadata["proxy_agent"] = proxy_agent
                version = proxy_agent

            server = headers.get("Server") or headers.get("server")
            if server:
                metadata["server"] = server
                if not version:
                    version = server

            if headers.get("Proxy-Authenticate") or headers.get("proxy-authenticate"):
                metadata["auth_required"] = True

            return ServiceIdentity(
                service="http_proxy",
                certainty=80,
                version=version,
                banner=response[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
