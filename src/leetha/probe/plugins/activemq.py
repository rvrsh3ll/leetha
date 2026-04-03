"""ActiveMQ probe plugin — OpenWire banner detection."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ActiveMQProbePlugin(ServiceProbe):
    name = "activemq"
    protocol = "tcp"
    default_ports = [61616]

    # OpenWire magic bytes
    OPENWIRE_MAGIC = b"\x00\x00\x00"  # length prefix (variable)
    ACTIVEMQ_MARKER = b"ActiveMQ"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # ActiveMQ sends its OpenWire banner upon connection
            data = conn.read(4096)
            if not data:
                return None

            # Check for ActiveMQ magic bytes in the data
            if self.ACTIVEMQ_MARKER not in data:
                return None

            metadata = {}
            version = None
            banner = None

            # Try to decode as text for banner
            try:
                text = data.decode("utf-8", errors="replace")
                banner = text.strip()
            except Exception:
                banner = data.hex()

            # Extract version info if available
            # OpenWire format includes version in the WireFormatInfo command
            # Look for version number pattern after ActiveMQ marker
            idx = data.find(self.ACTIVEMQ_MARKER)
            if idx >= 0:
                metadata["marker_offset"] = idx
                # After the marker, look for version-like patterns
                after_marker = data[idx:]
                try:
                    text_after = after_marker.decode("utf-8", errors="replace")
                    vm = re.search(r"(\d+\.\d+[\.\d]*)", text_after)
                    if vm:
                        version = vm.group(1)
                except Exception:
                    pass

            # Parse OpenWire protocol version from binary data
            # WireFormatInfo includes a version field
            if len(data) > 14:
                metadata["protocol"] = "openwire"

            return ServiceIdentity(
                service="activemq",
                certainty=90,
                version=version,
                banner=banner,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
