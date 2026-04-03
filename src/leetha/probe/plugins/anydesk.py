"""AnyDesk probe plugin — detect AnyDesk remote access via protocol signature."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class AnyDeskProbePlugin(ServiceProbe):
    name = "anydesk"
    protocol = "tcp"
    default_ports = [7070]

    # Known AnyDesk protocol signatures
    _ANYDESK_MAGIC = b"\x44\x45\x53\x4b"  # "DESK" in ASCII (AnyDesk marker)

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # AnyDesk uses a custom binary handshake
            # Send initial probe bytes to trigger a response
            conn.write(b"\x3e\xd1\x01\x00")
            data = conn.read(1024)
            if not data or len(data) < 4:
                return None

            metadata: dict = {
                "response_length": len(data),
                "response_prefix": data[:8].hex() if len(data) >= 8 else data.hex(),
            }

            # Check for AnyDesk protocol indicators
            # AnyDesk binary protocol has specific byte patterns
            detected = False

            # Check for "DESK" magic bytes anywhere in early response
            if self._ANYDESK_MAGIC in data[:64]:
                detected = True
                metadata["magic_found"] = True

            # Check for known AnyDesk handshake response pattern
            # AnyDesk often responds with specific byte sequences
            if data[:2] == b"\x3e\xd1":
                detected = True
                metadata["handshake_echo"] = True

            # Some AnyDesk versions respond with "AN" prefix bytes
            if data[:2] == b"AN" or b"anydesk" in data[:64].lower():
                detected = True
                metadata["anydesk_string"] = True

            if not detected:
                return None

            return ServiceIdentity(
                service="anydesk",
                certainty=75,
                version=None,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
