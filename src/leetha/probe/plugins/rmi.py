"""Java RMI probe plugin — RMI protocol handshake for Java service detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RMIProbePlugin(ServiceProbe):
    name = "rmi"
    protocol = "tcp"
    default_ports = [1099]

    # RMI magic bytes
    _JRMI_MAGIC = b"\x4a\x52\x4d\x49"  # "JRMI"
    _PROTOCOL_ACK = 0x4E
    _STREAM_PROTOCOL = 0x4B

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send RMI protocol header
            # Magic: JRMI (4 bytes)
            # Version: 2 (2 bytes)
            # Protocol: StreamProtocol (1 byte, 0x4B)
            header = self._JRMI_MAGIC
            header += struct.pack(">H", 2)  # Version 2
            header += struct.pack("B", self._STREAM_PROTOCOL)

            conn.write(header)
            data = conn.read(1024)
            if not data:
                return None

            metadata: dict = {}

            # Check for ProtocolAck (0x4E)
            if data[0] == self._PROTOCOL_ACK:
                metadata["protocol_ack"] = True
                # After ProtocolAck, there may be host/conn.port info
                # Format: ack(1) + host_length(2) + conn.host + port(4)
                if len(data) > 3:
                    host_len = struct.unpack(">H", data[1:3])[0]
                    if len(data) >= 3 + host_len:
                        remote_host = data[3:3 + host_len].decode("utf-8", errors="replace")
                        metadata["remote_host"] = remote_host
                        if len(data) >= 3 + host_len + 4:
                            remote_port = struct.unpack(">I", data[3 + host_len:7 + host_len])[0]
                            metadata["remote_port"] = remote_port

                return ServiceIdentity(
                    service="rmi",
                    certainty=85,
                    metadata=metadata,
                )

            # Check if server sent JRMI magic (banner-based detection)
            if data[:4] == self._JRMI_MAGIC:
                metadata["jrmi_banner"] = True
                if len(data) >= 6:
                    version = struct.unpack(">H", data[4:6])[0]
                    metadata["version"] = version
                return ServiceIdentity(
                    service="rmi",
                    certainty=85,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
