"""NFS probe plugin — RPC NULL call to detect NFS/RPC services."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NFSProbePlugin(ServiceProbe):
    name = "nfs"
    protocol = "tcp"
    default_ports = [2049, 111]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build RPC CALL message for NFS NULL procedure
            # RPC header
            xid = 0x12345678
            msg_type = 0  # CALL
            rpc_version = 2
            program = 100003  # NFS
            prog_version = 3
            procedure = 0  # NULL

            rpc_call = struct.pack(">I", xid)
            rpc_call += struct.pack(">I", msg_type)
            rpc_call += struct.pack(">I", rpc_version)
            rpc_call += struct.pack(">I", program)
            rpc_call += struct.pack(">I", prog_version)
            rpc_call += struct.pack(">I", procedure)
            # Auth: AUTH_NULL
            rpc_call += struct.pack(">II", 0, 0)  # flavor=NULL, length=0
            # Verifier: AUTH_NULL
            rpc_call += struct.pack(">II", 0, 0)  # flavor=NULL, length=0

            # TCP RPC: 4-byte record marker (last fragment bit set)
            record_marker = 0x80000000 | len(rpc_call)
            packet = struct.pack(">I", record_marker) + rpc_call

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 28:
                return None

            # Parse TCP record marker
            offset = 0
            rm = struct.unpack_from(">I", data, offset)[0]
            offset += 4

            # Parse RPC REPLY
            reply_xid = struct.unpack_from(">I", data, offset)[0]
            if reply_xid != xid:
                return None
            offset += 4

            reply_type = struct.unpack_from(">I", data, offset)[0]
            if reply_type != 1:  # REPLY
                return None
            offset += 4

            # Reply status: 0 = MSG_ACCEPTED
            reply_status = struct.unpack_from(">I", data, offset)[0]
            if reply_status != 0:
                return None
            offset += 4

            metadata: dict = {"rpc_program": program, "rpc_version": prog_version}

            # Skip verifier (flavor + length + data)
            if len(data) >= offset + 8:
                verf_flavor = struct.unpack_from(">I", data, offset)[0]
                offset += 4
                verf_len = struct.unpack_from(">I", data, offset)[0]
                offset += 4 + verf_len

                # Accept status: 0 = SUCCESS
                if len(data) >= offset + 4:
                    accept_status = struct.unpack_from(">I", data, offset)[0]
                    metadata["accept_status"] = accept_status

            return ServiceIdentity(
                service="nfs",
                certainty=80,
                version=None,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
