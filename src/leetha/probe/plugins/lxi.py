"""LXI/VXI-11 probe plugin — lab instrument control via ONC RPC portmapper."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

# VXI-11 program number
_VXI11_PROG = 395183
# Portmapper program and version
_PMAP_PROG = 100000
_PMAP_VERS = 2
# GETPORT procedure
_PMAP_GETPORT = 3
# RPC message type
_RPC_CALL = 0
_RPC_REPLY = 1
# Reply status
_MSG_ACCEPTED = 0

class LXIProbePlugin(ServiceProbe):
    name = "lxi"
    protocol = "tcp"
    default_ports = [111]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            rpc_msg = self._build_getport_request()
            # TCP RPC: prepend 4-byte fragment header (last fragment bit + length)
            frag_header = struct.pack(">I", 0x80000000 | len(rpc_msg))
            conn.write(frag_header + rpc_msg)
            data = conn.read(4096)
            if not data or len(data) < 28:
                return None

            # Skip TCP fragment header if present
            offset = 0
            if len(data) >= 4:
                possible_frag = struct.unpack(">I", data[0:4])[0]
                if possible_frag & 0x80000000:
                    offset = 4

            if offset + 24 > len(data):
                return None

            # Parse RPC reply header
            xid = struct.unpack(">I", data[offset:offset + 4])[0]
            msg_type = struct.unpack(">I", data[offset + 4:offset + 8])[0]

            if msg_type != _RPC_REPLY:
                return None

            reply_stat = struct.unpack(">I", data[offset + 8:offset + 12])[0]
            if reply_stat != _MSG_ACCEPTED:
                return None

            metadata: dict = {"rpc_reply": True}

            # Skip verifier: flavor(4) + length(4) + body
            verifier_offset = offset + 12
            if verifier_offset + 8 > len(data):
                return ServiceIdentity(
                    service="lxi", certainty=70, metadata=metadata
                )
            verf_len = struct.unpack(
                ">I", data[verifier_offset + 4:verifier_offset + 8]
            )[0]
            data_offset = verifier_offset + 8 + verf_len

            if data_offset + 8 > len(data):
                return ServiceIdentity(
                    service="lxi", certainty=70, metadata=metadata
                )

            accept_stat = struct.unpack(
                ">I", data[data_offset:data_offset + 4]
            )[0]
            metadata["accept_stat"] = accept_stat

            if accept_stat == 0 and data_offset + 8 <= len(data):
                vxi_port = struct.unpack(
                    ">I", data[data_offset + 4:data_offset + 8]
                )[0]
                metadata["vxi11_port"] = vxi_port
                if vxi_port > 0:
                    metadata["vxi11_available"] = True

            return ServiceIdentity(
                service="lxi",
                certainty=85,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _build_getport_request(self) -> bytes:
        """Build RPC GETPORT request for VXI-11 program."""
        xid = 0x12345678
        msg = struct.pack(">I", xid)           # XID
        msg += struct.pack(">I", _RPC_CALL)    # message type
        msg += struct.pack(">I", 2)            # RPC version
        msg += struct.pack(">I", _PMAP_PROG)   # program
        msg += struct.pack(">I", _PMAP_VERS)   # version
        msg += struct.pack(">I", _PMAP_GETPORT) # procedure
        # Auth: AUTH_NULL
        msg += struct.pack(">II", 0, 0)        # credential
        msg += struct.pack(">II", 0, 0)        # verifier
        # GETPORT args: program, version, protocol(TCP=6), port=0
        msg += struct.pack(">I", _VXI11_PROG)
        msg += struct.pack(">I", 1)            # version 1
        msg += struct.pack(">I", 6)            # TCP
        msg += struct.pack(">I", 0)            # conn.port (unused)
        return msg
