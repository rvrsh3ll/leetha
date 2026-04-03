"""Rlogin probe plugin — detect rlogin service via null-byte handshake."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RloginProbePlugin(ServiceProbe):
    name = "rlogin"
    protocol = "tcp"
    default_ports = [513]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Rlogin protocol:
            # 1. Client sends: \x00
            # 2. Client sends: client_username\x00server_username\x00terminal_type/speed\x00
            # 3. Server responds with \x00 on success

            # Send initial null byte
            conn.write(b"\x00")

            # Send login string: client_user\0server_user\0terminal/baud\0
            login_data = b"probe\x00probe\x00xterm/38400\x00"
            conn.write(login_data)

            data = conn.read(1024)
            if not data:
                return None

            metadata: dict = {}

            # Rlogin server responds with a null byte to indicate ready
            if data[0:1] == b"\x00":
                metadata["accepted"] = True
                # There may be additional data after the null byte (login prompt, etc.)
                if len(data) > 1:
                    extra = data[1:].decode("utf-8", errors="replace").strip()
                    if extra:
                        metadata["banner"] = extra[:256]

                return ServiceIdentity(
                    service="rlogin",
                    certainty=75,
                    version=None,
                    banner=metadata.get("banner"),
                    metadata=metadata,
                )

            # Some rlogin daemons may send an error message or prompt directly
            text = data.decode("utf-8", errors="replace").strip()
            if text and ("login" in text.lower() or "password" in text.lower()
                         or "permission" in text.lower()):
                metadata["banner"] = text[:256]
                return ServiceIdentity(
                    service="rlogin",
                    certainty=65,
                    version=None,
                    banner=text[:256],
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError):
            return None
