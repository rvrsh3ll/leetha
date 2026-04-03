"""IPFIX probe plugin — send IPFIX template message and check for response."""
from __future__ import annotations
import socket
import struct
import time
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IPFIXProbePlugin(ServiceProbe):
    name = "ipfix"
    protocol = "udp"
    default_ports = [4739]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal IPFIX message header (RFC 7011)
            # Version: 0x000a (10)
            # Length: 16 (header only)
            # Export Time: current timestamp
            # Sequence Number: 0
            # Observation Domain ID: 1
            export_time = int(time.time())
            message = struct.pack(
                ">HHIII",
                0x000A,       # version
                16,           # length (header only)
                export_time,  # export time
                0,            # sequence number
                1,            # observation domain ID
            )
            conn.write(message)

            conn.set_timeout(3)
            try:
                data = conn.read(4096)
            except socket.timeout:
                return None

            if not data or len(data) < 16:
                return None

            # Check for IPFIX response header
            if len(data) >= 2:
                resp_version = struct.unpack(">H", data[:2])[0]
                if resp_version != 0x000A:
                    return None

            resp_length = struct.unpack(">H", data[2:4])[0]
            metadata: dict = {
                "version": 10,
                "response_length": resp_length,
            }

            return ServiceIdentity(
                service="ipfix",
                certainty=80,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
