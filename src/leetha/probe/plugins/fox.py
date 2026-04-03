"""Tridium Fox (Niagara) probe plugin — Fox hello handshake."""
from __future__ import annotations

import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FoxProbePlugin(ServiceProbe):
    name = "fox"
    protocol = "tcp"
    default_ports = [1911, 4911]

    # Fox hello message
    FOX_HELLO = (
        b"fox a 1 -1 fox hello\n"
        b"{\n"
        b"fox.version=s:1.0\n"
        b"id=i:1\n"
        b"};;\n"
    )

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(self.FOX_HELLO)
            data = conn.read(4096)
            if not data:
                return None

            # Try to decode response as text
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = data.decode("ascii", errors="replace")

            # Check for Fox protocol markers
            text_lower = text.lower()
            if "fox" not in text_lower:
                return None

            metadata = {}

            # Parse key-value pairs from response
            self._parse_fox_response(text, metadata)

            version = metadata.get("fox.version") or metadata.get("app.version")
            return ServiceIdentity(
                service="fox",
                certainty=85,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError):
            return None

    def _parse_fox_response(self, text: str, metadata: dict) -> None:
        """Parse Fox protocol key-value response."""
        try:
            for line in text.split("\n"):
                line = line.strip()
                if "=" in line:
                    # Fox format: key=type:value
                    key, _, value_part = line.partition("=")
                    key = key.strip()
                    value_part = value_part.strip()
                    # Parse type:value format
                    if ":" in value_part:
                        _type_prefix, _, value = value_part.partition(":")
                        metadata[key] = value.strip()
                    else:
                        metadata[key] = value_part

                # Look for conn.host name in the header line
                if line.startswith("fox "):
                    metadata["header"] = line
        except Exception:
            pass
