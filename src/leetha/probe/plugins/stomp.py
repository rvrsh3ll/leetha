"""STOMP probe plugin — messaging protocol detection."""
from __future__ import annotations

import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class STOMPProbePlugin(ServiceProbe):
    name = "stomp"
    protocol = "tcp"
    default_ports = [61613]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send STOMP CONNECT frame
            # The frame ends with a null byte
            connect_frame = (
                "CONNECT\n"
                "accept-version:1.2\n"
                "host:localhost\n"
                "\n\x00"
            )
            conn.write(connect_frame.encode("utf-8"))
            data = conn.read(4096)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # STOMP server responds with CONNECTED or ERROR frame
            if not text.startswith("CONNECTED") and not text.startswith("ERROR"):
                return None

            metadata = {}
            version = None
            banner = text.strip().replace("\x00", "")

            # Parse headers from the response
            lines = text.split("\n")
            frame_type = lines[0].strip()
            metadata["frame_type"] = frame_type

            for line in lines[1:]:
                line = line.strip().replace("\x00", "")
                if not line:
                    break
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip().lower()
                    val = val.strip()
                    if key == "version":
                        version = val
                        metadata["protocol_version"] = val
                    elif key == "server":
                        metadata["server"] = val
                    elif key == "heart-beat":
                        metadata["heart_beat"] = val
                    elif key == "session":
                        metadata["session"] = val
                    elif key == "message":
                        metadata["error_message"] = val

            confidence = 90 if frame_type == "CONNECTED" else 80

            return ServiceIdentity(
                service="stomp",
                certainty=confidence,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
