"""JMX probe plugin — JMX over RMI detection for Java management interface."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class JMXProbePlugin(ServiceProbe):
    name = "jmx"
    protocol = "tcp"
    default_ports = [9010, 9011, 1099]

    # RMI/JMX magic bytes
    _JRMI_MAGIC = b"\x4a\x52\x4d\x49"  # "JRMI"
    _PROTOCOL_ACK = 0x4E
    _STREAM_PROTOCOL = 0x4B

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send RMI protocol header (JMX uses RMI under the hood)
            # Magic: JRMI (4 bytes)
            # Version: 2 (2 bytes)
            # Protocol: StreamProtocol (1 byte, 0x4B)
            header = self._JRMI_MAGIC
            header += struct.pack(">H", 2)  # Version 2
            header += struct.pack("B", self._STREAM_PROTOCOL)

            conn.write(header)
            data = conn.read(4096)
            if not data:
                return None

            metadata: dict = {}

            # Check for ProtocolAck (0x4E) — standard RMI/JMX response
            if data[0] == self._PROTOCOL_ACK:
                metadata["protocol_ack"] = True

                # Parse host/conn.port info after ProtocolAck
                if len(data) > 3:
                    host_len = struct.unpack(">H", data[1:3])[0]
                    if len(data) >= 3 + host_len:
                        remote_host = data[3:3 + host_len].decode("utf-8", errors="replace")
                        metadata["remote_host"] = remote_host
                        if len(data) >= 3 + host_len + 4:
                            remote_port = struct.unpack(">I", data[3 + host_len:7 + host_len])[0]
                            metadata["remote_port"] = remote_port

                # Check remaining data for JMX-specific stubs
                # JMX RMI stubs often contain "javax.management" or "jmxrmi" strings
                full_data = data
                try:
                    remaining = full_data.decode("utf-8", errors="replace")
                    if "javax.management" in remaining or "jmxrmi" in remaining:
                        metadata["jmx_stub"] = True
                    if "javax.management" in remaining:
                        metadata["jmx_management"] = True
                except Exception:
                    pass

                return ServiceIdentity(
                    service="jmx",
                    certainty=80,
                    metadata=metadata,
                )

            # Check if server sent JRMI magic (banner-based detection)
            if data[:4] == self._JRMI_MAGIC:
                metadata["jrmi_banner"] = True
                if len(data) >= 6:
                    version = struct.unpack(">H", data[4:6])[0]
                    metadata["version"] = version
                return ServiceIdentity(
                    service="jmx",
                    certainty=80,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
