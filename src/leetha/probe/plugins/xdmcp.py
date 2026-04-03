"""XDMCP probe plugin — Query packet to detect X Display Manager services."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class XDMCPProbePlugin(ServiceProbe):
    name = "xdmcp"
    protocol = "udp"
    default_ports = [177]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build XDMCP Query packet
            # Version(2) + Opcode(2) + Length(2) + data
            # Version 1, Opcode 2 (Query), Length = 1 (array count)
            # Authentication names array: count=0
            query = struct.pack(">HHH", 1, 2, 1)  # version, opcode=Query, length
            query += struct.pack(">B", 0)  # Array count (no auth names)

            conn.write(query)
            data = conn.read(1024)
            if not data or len(data) < 6:
                return None

            # Parse XDMCP response header
            version = struct.unpack_from(">H", data, 0)[0]
            opcode = struct.unpack_from(">H", data, 2)[0]
            length = struct.unpack_from(">H", data, 4)[0]

            # Check for Willing response (opcode 5) or Unwilling (opcode 6)
            if opcode not in (5, 6):
                return None

            metadata: dict = {
                "xdmcp_version": version,
                "opcode": opcode,
            }

            offset = 6
            if opcode == 5:
                # Willing response contains:
                # authentication_name (ARRAY8) + hostname (ARRAY8) + status (ARRAY8)
                metadata["willing"] = True

                # Parse ARRAY8: 2-byte length + data
                if len(data) >= offset + 2:
                    auth_len = struct.unpack_from(">H", data, offset)[0]
                    offset += 2
                    if len(data) >= offset + auth_len:
                        auth_name = data[offset:offset + auth_len].decode(
                            "utf-8", errors="replace"
                        )
                        if auth_name:
                            metadata["auth_name"] = auth_name
                        offset += auth_len

                # Hostname
                if len(data) >= offset + 2:
                    host_len = struct.unpack_from(">H", data, offset)[0]
                    offset += 2
                    if len(data) >= offset + host_len:
                        hostname = data[offset:offset + host_len].decode(
                            "utf-8", errors="replace"
                        )
                        if hostname:
                            metadata["hostname"] = hostname
                        offset += host_len

                # Status
                if len(data) >= offset + 2:
                    status_len = struct.unpack_from(">H", data, offset)[0]
                    offset += 2
                    if len(data) >= offset + status_len:
                        status = data[offset:offset + status_len].decode(
                            "utf-8", errors="replace"
                        )
                        if status:
                            metadata["status"] = status

            elif opcode == 6:
                metadata["willing"] = False

            return ServiceIdentity(
                service="xdmcp",
                certainty=80,
                version=None,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
