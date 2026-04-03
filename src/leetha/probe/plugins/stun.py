"""STUN probe plugin — Session Traversal Utilities for NAT."""
from __future__ import annotations
import os
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class STUNProbePlugin(ServiceProbe):
    name = "stun"
    protocol = "udp"
    default_ports = [3478, 5349]

    MAGIC_COOKIE = 0x2112A442

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # STUN Binding Request
            msg_type = 0x0001  # Binding Request
            msg_length = 0  # No attributes
            transaction_id = os.urandom(12)

            request = struct.pack(
                ">HHI", msg_type, msg_length, self.MAGIC_COOKIE
            ) + transaction_id

            conn.write(request)
            data = conn.read(4096)

            if not data or len(data) < 20:
                return None

            # Parse STUN header
            resp_type, resp_length, magic = struct.unpack(">HHI", data[0:8])
            resp_txn_id = data[8:20]

            # Check magic cookie
            if magic != self.MAGIC_COOKIE:
                return None

            # Check for Binding Response (0x0101) or Binding Error (0x0111)
            if resp_type not in (0x0101, 0x0111):
                return None

            # Verify transaction ID matches
            if resp_txn_id != transaction_id:
                return None

            metadata: dict = {
                "response_type": hex(resp_type),
                "message_length": resp_length,
            }

            # Try to parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attributes
            offset = 20
            while offset + 4 <= len(data):
                attr_type, attr_length = struct.unpack(">HH", data[offset:offset + 4])
                offset += 4

                if offset + attr_length > len(data):
                    break

                if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                    if attr_length >= 8:
                        family = data[offset + 1]
                        xport = struct.unpack(">H", data[offset + 2:offset + 4])[0]
                        port_val = xport ^ (self.MAGIC_COOKIE >> 16)
                        if family == 0x01:  # IPv4
                            xaddr = struct.unpack(">I", data[offset + 4:offset + 8])[0]
                            addr = xaddr ^ self.MAGIC_COOKIE
                            ip = socket.inet_ntoa(struct.pack(">I", addr))
                            metadata["mapped_address"] = ip
                            metadata["mapped_port"] = port_val
                elif attr_type == 0x0001:  # MAPPED-ADDRESS
                    if attr_length >= 8:
                        family = data[offset + 1]
                        port_val = struct.unpack(">H", data[offset + 2:offset + 4])[0]
                        if family == 0x01:  # IPv4
                            ip = socket.inet_ntoa(data[offset + 4:offset + 8])
                            metadata["mapped_address"] = ip
                            metadata["mapped_port"] = port_val

                # Pad to 4-byte boundary
                offset += attr_length
                if attr_length % 4 != 0:
                    offset += 4 - (attr_length % 4)

            return ServiceIdentity(
                service="stun",
                certainty=80,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
