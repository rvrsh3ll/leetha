"""TFTP probe plugin — UDP read request to detect TFTP services."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TFTPProbePlugin(ServiceProbe):
    name = "tftp"
    protocol = "udp"
    default_ports = [69]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send RRQ (Read Request) for a non-existent file
            # Opcode 1 (RRQ) + filename + \x00 + mode + \x00
            rrq = b"\x00\x01test\x00octet\x00"
            conn.write(rrq)
            data = conn.read(1024)
            if not data or len(data) < 4:
                return None

            # Parse TFTP response opcode
            opcode = struct.unpack(">H", data[0:2])[0]
            metadata: dict = {"opcode": opcode}

            if opcode == 5:
                # ERROR packet: opcode(2) + error_code(2) + error_msg + \x00
                error_code = struct.unpack(">H", data[2:4])[0]
                metadata["error_code"] = error_code
                # Extract error message
                if len(data) > 4:
                    error_msg = data[4:].split(b"\x00", 1)[0]
                    metadata["error_message"] = error_msg.decode("utf-8", errors="replace")
                return ServiceIdentity(
                    service="tftp",
                    certainty=80,
                    version=None,
                    banner=None,
                    metadata=metadata,
                )
            elif opcode == 3:
                # DATA packet — also indicates TFTP service
                metadata["data_received"] = True
                return ServiceIdentity(
                    service="tftp",
                    certainty=80,
                    version=None,
                    banner=None,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
