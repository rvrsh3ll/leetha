"""GlusterFS probe plugin — sends GlusterFS RPC handshake to detect the daemon."""
from __future__ import annotations
import struct
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GlusterFSProbePlugin(ServiceProbe):
    name = "glusterfs"
    protocol = "tcp"
    default_ports = [24007]

    # GlusterFS RPC constants
    _GF_DUMP_PROGRAM = 123451501
    _GF_DUMP_VERSION = 1
    _PROC_NULL = 0

    def _build_rpc_call(self) -> bytes:
        """Build an ONC-RPC call for GlusterFS DUMP program, NULL procedure."""
        xid = 0x00000001
        msg_type = 0  # CALL
        rpc_version = 2
        program = self._GF_DUMP_PROGRAM
        prog_version = self._GF_DUMP_VERSION
        procedure = self._PROC_NULL
        # Auth: AUTH_NULL (flavor=0, length=0)
        auth_null = struct.pack(">II", 0, 0)

        body = struct.pack(
            ">IIIIII",
            xid,
            msg_type,
            rpc_version,
            program,
            prog_version,
            procedure,
        )
        body += auth_null  # credential
        body += auth_null  # verifier

        # RPC record marker: last fragment (bit 31 set) + length
        fragment_header = struct.pack(">I", 0x80000000 | len(body))
        return fragment_header + body

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            packet = self._build_rpc_call()
            conn.write(packet)

            data = conn.read(4096)
            if not data:
                return None

            # Minimum RPC reply: fragment header (4) + xid (4) + msg_type (4) + reply_stat (4) = 16
            if len(data) < 16:
                return None

            # Parse fragment header
            frag_header = struct.unpack(">I", data[:4])[0]
            frag_len = frag_header & 0x7FFFFFFF

            # Parse RPC reply
            if len(data) < 8:
                return None

            xid, msg_type = struct.unpack(">II", data[4:12])

            # msg_type must be 1 (REPLY)
            if msg_type != 1:
                return None

            # xid should match what we sent
            if xid != 0x00000001:
                return None

            metadata: dict = {
                "xid": xid,
                "fragment_length": frag_len,
            }

            # Check reply status (offset 12)
            if len(data) >= 16:
                reply_stat = struct.unpack(">I", data[12:16])[0]
                metadata["reply_stat"] = reply_stat
                # 0 = MSG_ACCEPTED, 1 = MSG_DENIED
                if reply_stat == 0:
                    metadata["status"] = "accepted"
                else:
                    metadata["status"] = "denied"

            return ServiceIdentity(
                service="glusterfs",
                certainty=85,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
