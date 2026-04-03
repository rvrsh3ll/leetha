"""sFlow probe plugin — send minimal sFlow v5 datagram and check for response."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SFlowProbePlugin(ServiceProbe):
    name = "sflow"
    protocol = "udp"
    default_ports = [6343]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal sFlow v5 datagram header
            # Version: 5
            # Agent address type: 1 (IPv4)
            # Agent address: 127.0.0.1
            # Sub-agent ID: 0
            # Sequence number: 1
            # Uptime: 1000 (ms)
            # Number of samples: 0
            datagram = struct.pack(
                ">IIIIIIII",
                5,            # version
                1,            # agent address type (IPv4)
                0x7F000001,   # agent address (127.0.0.1)
                0,            # sub-agent ID
                1,            # sequence number
                1000,         # uptime (ms)
                0,            # number of samples
                0,            # padding
            )
            # Trim the trailing padding word
            datagram = datagram[:28]

            conn.write(datagram)

            conn.set_timeout(3)
            try:
                data = conn.read(4096)
            except socket.timeout:
                return None

            if not data or len(data) < 4:
                return None

            # Check for sFlow response (version field should be 5)
            resp_version = struct.unpack(">I", data[:4])[0]
            if resp_version != 5:
                return None

            metadata: dict = {"version": 5}

            if len(data) >= 8:
                addr_type = struct.unpack(">I", data[4:8])[0]
                metadata["agent_address_type"] = addr_type

            return ServiceIdentity(
                service="sflow",
                certainty=75,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
