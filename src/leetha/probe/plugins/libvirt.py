"""Libvirt probe plugin — connects to libvirtd and sends QEMU protocol probe."""
from __future__ import annotations

import re
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LibvirtProbePlugin(ServiceProbe):
    name = "libvirt"
    protocol = "tcp"
    default_ports = [16509]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # libvirtd uses a custom RPC protocol.
            # When connecting, we can send a minimal program call and look for
            # a libvirt-style response, or the daemon may reject with an error
            # that reveals itself.
            # A simpler approach: send a probe string and check if the response
            # contains libvirt indicators. The libvirt remote protocol uses
            # XDR-encoded RPC. We'll send a minimal REMOTE_PROC_CONNECT_OPEN
            # call (program=0x20008086, version=1, proc=1).

            # Libvirt RPC header:
            # program (4 bytes) + version (4 bytes) + procedure (4 bytes) +
            # type (4 bytes: 0=call) + serial (4 bytes) + status (4 bytes: 0=ok)
            import struct

            program = 0x20008086  # REMOTE_PROGRAM
            version = 1
            procedure = 1  # REMOTE_PROC_CONNECT_OPEN
            msg_type = 0  # CALL
            serial = 1
            status = 0  # OK

            header = struct.pack(
                ">IIIIII", program, version, procedure, msg_type, serial, status
            )
            # Add name parameter (empty string = default URI) + flags (0)
            # XDR string: length (4 bytes) + data + padding
            name_str = b""
            name_field = struct.pack(">I", len(name_str)) + name_str
            flags_field = struct.pack(">I", 0)
            payload = header + name_field + flags_field

            # Libvirt frames: length prefix (4 bytes, includes itself)
            frame = struct.pack(">I", len(payload) + 4) + payload

            conn.write(frame)
            data = conn.read(4096)
            if not data or len(data) < 28:
                return None

            # Parse response frame
            if len(data) < 4:
                return None

            resp_len = struct.unpack(">I", data[:4])[0]
            if resp_len < 28:
                return None

            resp_data = data[4:]
            if len(resp_data) < 24:
                return None

            resp_program = struct.unpack(">I", resp_data[0:4])[0]
            resp_version = struct.unpack(">I", resp_data[4:8])[0]
            resp_procedure = struct.unpack(">I", resp_data[8:12])[0]
            resp_type = struct.unpack(">I", resp_data[12:16])[0]
            resp_serial = struct.unpack(">I", resp_data[16:20])[0]
            resp_status = struct.unpack(">I", resp_data[20:24])[0]

            # Check for libvirt program magic
            if resp_program != 0x20008086:
                return None

            metadata: dict = {
                "protocol_version": resp_version,
                "response_type": "reply" if resp_type == 1 else str(resp_type),
                "response_status": "ok" if resp_status == 0 else "error",
            }

            version = None
            if resp_version:
                version = str(resp_version)

            return ServiceIdentity(
                service="libvirt",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
