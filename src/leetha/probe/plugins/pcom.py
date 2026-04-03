"""Unitronics PCOM probe plugin — ASCII ID command for PLC identification."""
from __future__ import annotations

import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PCOMProbePlugin(ServiceProbe):
    name = "pcom"
    protocol = "tcp"
    default_ports = [20256]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # PCOM ASCII protocol
            # Frame: STX('/') + UnitID(2) + Command + Data + Checksum(2) + ETX('\r')
            # ID command to get PLC model information
            unit_id = "00"
            command = "ID"

            # Build the message (without checksum initially)
            message = unit_id + command

            # Calculate checksum: sum of ASCII values mod 256, as 2-char hex
            checksum = sum(ord(c) for c in message) % 256
            checksum_str = f"{checksum:02X}"

            # Full PCOM ASCII frame
            request = f"/{message}{checksum_str}\r".encode("ascii")

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 4:
                return None

            # Try to decode response as ASCII
            try:
                text = data.decode("ascii", errors="replace")
            except Exception:
                return None

            # Validate PCOM response format
            # Should start with '/' (STX) and contain unit ID
            if not text.startswith("/"):
                return None

            metadata = {}

            # Parse response
            # Strip STX and ETX
            content = text.lstrip("/")
            if "\r" in content:
                content = content[:content.index("\r")]

            # Unit ID is first 2 characters
            if len(content) >= 2:
                resp_unit_id = content[:2]
                metadata["unit_id"] = resp_unit_id

            # The rest contains the response data (before checksum)
            if len(content) > 4:
                # Last 2 chars before ETX are checksum
                resp_data = content[2:-2] if len(content) > 4 else content[2:]
                metadata["response_data"] = resp_data

                # Parse model info from response
                self._parse_id_response(resp_data, metadata)

            return ServiceIdentity(
                service="pcom",
                certainty=85,
                version=metadata.get("model"),
                metadata=metadata,
            )

        except (socket.timeout, OSError):
            return None

    def _parse_id_response(self, data: str, metadata: dict) -> None:
        """Parse the ID command response to extract PLC model information."""
        try:
            if not data:
                return
            # The ID response typically contains model and version info
            # Format varies by PLC model, but generally contains alphanumeric strings
            if len(data) >= 2:
                # Command echo or response code
                metadata["response_code"] = data[:2]
            if len(data) > 2:
                info = data[2:]
                # Extract readable segments
                segments = []
                current: list[str] = []
                for ch in info:
                    if ch.isalnum() or ch in ".-_/ ":
                        current.append(ch)
                    else:
                        if len(current) >= 2:
                            segments.append("".join(current).strip())
                        current = []
                if len(current) >= 2:
                    segments.append("".join(current).strip())

                if segments:
                    metadata["model"] = segments[0]
                if len(segments) > 1:
                    metadata["plc_version"] = segments[1]
        except Exception:
            pass
