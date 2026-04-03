"""NTP probe plugin — version query."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NTPProbePlugin(ServiceProbe):
    name = "ntp"
    protocol = "udp"
    default_ports = [123]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # NTP version request (mode 3 - client, version 4)
            packet = b"\xe3" + b"\x00" * 47  # LI=3, VN=4, Mode=3
            conn.write(packet)
            data = conn.read(1024)
            if not data or len(data) < 48:
                return None
            # Check for valid NTP response (mode 4 = server)
            mode = data[0] & 0x07
            version = (data[0] >> 3) & 0x07
            if mode != 4:
                return None
            stratum = data[1]
            metadata = {"version": version, "stratum": stratum}
            return ServiceIdentity(service="ntp", certainty=85, metadata=metadata)
        except (socket.timeout, OSError):
            return None
