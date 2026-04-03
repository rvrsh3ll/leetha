"""XMPP probe plugin — stream opening."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class XMPPProbePlugin(ServiceProbe):
    name = "xmpp"
    protocol = "tcp"
    default_ports = [5222, 5269, 5280]

    STREAM_OPEN = (
        "<?xml version='1.0'?>"
        "<stream:stream to='localhost' "
        "xmlns='jabber:client' "
        "xmlns:stream='http://etherx.jabber.org/streams' "
        "version='1.0'>"
    )

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(self.STREAM_OPEN.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None
            response = data.decode("utf-8", errors="replace")

            if "<stream:stream" not in response and "<?xml" not in response:
                return None

            metadata = {}
            version = None
            banner = response.strip()

            # Extract stream version
            vm = re.search(r'version=["\']([^"\']+)["\']', response)
            if vm:
                version = vm.group(1)

            # Extract stream id
            sid = re.search(r'id=["\']([^"\']+)["\']', response)
            if sid:
                metadata["stream_id"] = sid.group(1)

            # Extract from attribute
            fm = re.search(r'\bfrom=["\']([^"\']+)["\']', response)
            if fm:
                metadata["from"] = fm.group(1)

            # Check for stream features
            features = []
            if "<starttls" in response.lower():
                features.append("starttls")
            if "<mechanisms" in response.lower():
                features.append("sasl")
            if "<bind" in response.lower():
                features.append("bind")
            if features:
                metadata["features"] = features

            return ServiceIdentity(
                service="xmpp",
                certainty=85,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
