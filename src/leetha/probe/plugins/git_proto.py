"""Git protocol probe plugin — git-upload-pack request to detect Git daemon."""
from __future__ import annotations
import re
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GitProtoProbePlugin(ServiceProbe):
    name = "git_proto"
    protocol = "tcp"
    default_ports = [9418]

    # Git pkt-line format: 4 hex digits length + payload
    _PKT_LINE_RE = re.compile(r"^[0-9a-fA-F]{4}")
    _SHA1_RE = re.compile(r"[0-9a-fA-F]{40}")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send git-upload-pack request in pkt-line format
            # Format: 4-hex-digit length + payload
            payload = b"git-upload-pack /\x00host=localhost\x00"
            pkt_line = f"{len(payload) + 4:04x}".encode() + payload
            conn.write(pkt_line)

            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            metadata: dict = {}

            # Check for valid pkt-line response
            if not self._PKT_LINE_RE.match(response):
                # Also check for ERR response
                if b"ERR " in data or b"error" in data.lower():
                    metadata["error"] = True
                    return ServiceIdentity(
                        service="git_proto",
                        certainty=75,
                        version=None,
                        banner=response[:256],
                        metadata=metadata,
                    )
                return None

            # Look for SHA1 hashes in response (pack advertisement)
            sha_matches = self._SHA1_RE.findall(response)
            if sha_matches:
                metadata["refs_found"] = len(sha_matches)

            # Check for capabilities
            if "capabilities" in response or "\x00" in response:
                metadata["has_capabilities"] = True

            # Look for version info
            version_match = re.search(r"version\s+(\d+)", response)
            version = version_match.group(1) if version_match else None

            return ServiceIdentity(
                service="git_proto",
                certainty=85,
                version=version,
                banner=response[:512],
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
