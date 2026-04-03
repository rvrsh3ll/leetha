"""MikroTik RouterOS API probe plugin — detects RouterOS via API login packet."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MikroTikProbePlugin(ServiceProbe):
    name = "mikrotik"
    protocol = "tcp"
    default_ports = [8728, 8729]

    @staticmethod
    def _encode_word(word: str) -> bytes:
        """Encode a RouterOS API word with length prefix."""
        encoded = word.encode("utf-8")
        length = len(encoded)
        if length < 0x80:
            return bytes([length]) + encoded
        if length < 0x4000:
            length |= 0x8000
            return length.to_bytes(2, "big") + encoded
        return bytes([length]) + encoded

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send RouterOS API /login command
            packet = self._encode_word("/login")
            # Empty word terminates the sentence
            packet += b"\x00"
            conn.write(packet)

            data = conn.read(4096)
            if not data:
                return None

            response = data.decode("utf-8", errors="replace")
            resp_lower = response.lower()

            metadata: dict = {}
            version = None

            # Check for RouterOS API response markers
            has_done = "!done" in resp_lower
            has_routeros = "routeros" in resp_lower
            has_trap = "!trap" in resp_lower
            has_fatal = "!fatal" in resp_lower

            if not (has_done or has_routeros or has_trap or has_fatal):
                return None

            if has_done:
                metadata["api_response"] = "done"
            elif has_trap:
                metadata["api_response"] = "trap"
            elif has_fatal:
                metadata["api_response"] = "fatal"

            if has_routeros:
                metadata["platform"] = "RouterOS"

            # Try to extract version from response
            # RouterOS may include version info in banner or challenge response
            for line in response.split("\n"):
                if "routeros" in line.lower():
                    parts = line.strip().split()
                    for part in parts:
                        if part and part[0].isdigit() and "." in part:
                            version = part
                            metadata["routeros_version"] = version
                            break

            return ServiceIdentity(
                service="mikrotik",
                certainty=85,
                version=version,
                metadata=metadata,
                banner=response[:256],
            )
        except (socket.timeout, OSError):
            return None
