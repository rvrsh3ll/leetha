"""SNMP probe plugin — v2c GET sysDescr."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SNMPProbePlugin(ServiceProbe):
    name = "snmp"
    protocol = "udp"
    default_ports = [161]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # SNMPv2c GET request for sysDescr.0 (1.3.6.1.2.1.1.1.0)
            # Community: "public"
            packet = bytes([
                0x30, 0x29,  # SEQUENCE
                0x02, 0x01, 0x01,  # version: v2c (1)
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # community: "public"
                0xa0, 0x1c,  # GetRequest
                0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # request-id: 1
                0x02, 0x01, 0x00,  # error-status: 0
                0x02, 0x01, 0x00,  # error-index: 0
                0x30, 0x0e,  # varbind list
                0x30, 0x0c,  # varbind
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID: 1.3.6.1.2.1.1.1.0
                0x05, 0x00,  # NULL value
            ])
            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 10:
                return None
            # Check for SNMP response (starts with SEQUENCE tag 0x30)
            if data[0] != 0x30:
                return None
            # Try to extract sysDescr value
            decoded = data.decode("utf-8", errors="replace")
            metadata = {"raw_length": len(data)}
            return ServiceIdentity(service="snmp", certainty=85, metadata=metadata, banner=decoded[:200])
        except (socket.timeout, OSError):
            return None
