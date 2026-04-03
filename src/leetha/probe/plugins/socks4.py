"""SOCKS4 probe plugin — SOCKS version 4 proxy detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SOCKS4ProbePlugin(ServiceProbe):
    name = "socks4"
    protocol = "tcp"
    default_ports = [1080]

    STATUS_CODES = {
        0x5A: "granted",
        0x5B: "rejected",
        0x5C: "failed_no_identd",
        0x5D: "failed_identd_mismatch",
    }

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # SOCKS4 CONNECT request
            # Version: 0x04, Command: 0x01 (CONNECT)
            # Destination port: 80 (HTTP), Destination IP: 93.184.216.34 (example.com)
            dest_port = 80
            dest_ip = socket.inet_aton("93.184.216.34")
            userid = b""

            request = struct.pack(
                ">BBH", 0x04, 0x01, dest_port
            ) + dest_ip + userid + b"\x00"

            conn.write(request)
            data = conn.read(4096)

            if not data or len(data) < 8:
                return None

            # SOCKS4 response: null byte + status + port(2) + ip(4)
            null_byte = data[0]
            status = data[1]

            if null_byte != 0x00:
                return None

            if status not in self.STATUS_CODES:
                return None

            metadata: dict = {
                "status": status,
                "status_text": self.STATUS_CODES.get(status, "unknown"),
            }

            return ServiceIdentity(
                service="socks4",
                certainty=85,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
