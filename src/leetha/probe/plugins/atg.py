"""Automatic Tank Gauge (TLS/ATG) probe plugin — Inventory command I20100."""
from __future__ import annotations

import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ATGProbePlugin(ServiceProbe):
    name = "atg"
    protocol = "tcp"
    default_ports = [10001]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # ATG TLS (Tank Level System) Inventory command
            # SOH (0x01) + command "I20100" + newline
            # I20100 = In-Tank Inventory report for all tanks
            request = b"\x01I20100\n"

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 2:
                return None

            # Check for SOH (0x01) prefix in response
            if data[0] != 0x01:
                return None

            metadata = {}

            # Try to decode the response
            try:
                text = data[1:].decode("ascii", errors="replace")
            except Exception:
                text = ""

            metadata["raw_response_length"] = len(data)

            # Parse inventory data
            if text:
                self._parse_inventory(text, metadata)

            return ServiceIdentity(
                service="atg",
                certainty=85,
                metadata=metadata,
            )

        except (socket.timeout, OSError):
            return None

    def _parse_inventory(self, text: str, metadata: dict) -> None:
        """Parse ATG inventory response text."""
        try:
            lines = text.strip().split("\n")
            if lines:
                # First line often contains system date/time or station ID
                header = lines[0].strip()
                if header:
                    metadata["header"] = header

            # Look for tank data lines
            tank_count = 0
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                # Tank data lines typically contain volume/height data
                # with numeric values separated by spaces or tabs
                if any(c.isdigit() for c in line):
                    tank_count += 1

            if tank_count > 0:
                metadata["tank_lines"] = tank_count

            # Store full response text (truncated)
            full_text = "\n".join(lines)
            if len(full_text) > 500:
                full_text = full_text[:500] + "..."
            metadata["response_text"] = full_text
        except Exception:
            pass
