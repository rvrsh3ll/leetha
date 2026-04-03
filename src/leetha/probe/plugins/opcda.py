"""OPC DA probe plugin — Classic OPC via DCERPC/DCOM."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

# IOPCServer interface UUID: {39C13A4D-011E-11D0-9675-0020AFD8ADB3}
_OPC_SERVER_UUID = (
    b"\x4d\x3a\xc1\x39\x1e\x01\xd0\x11"
    b"\x96\x75\x00\x20\xaf\xd8\xad\xb3"
)

# DCERPC bind_ack type
_DCERPC_BIND_ACK = 12

class OPCDAProbePlugin(ServiceProbe):
    name = "opcda"
    protocol = "tcp"
    default_ports = [135]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            bind_pdu = self._build_dcerpc_bind()
            conn.write(bind_pdu)
            data = conn.read(4096)
            if not data or len(data) < 24:
                return None

            # DCERPC header: version(1) + minor(1) + pdu_type(1)
            version = data[0]
            minor = data[1]
            pdu_type = data[2]

            if version != 5 or minor not in (0, 1):
                return None

            # bind_ack = 12, bind_nak = 13
            if pdu_type not in (_DCERPC_BIND_ACK, 13):
                return None

            metadata: dict = {
                "dcerpc_version": f"{version}.{minor}",
                "pdu_type": pdu_type,
            }

            if pdu_type == _DCERPC_BIND_ACK:
                metadata["bind_accepted"] = True
                # Parse context results to check acceptance
                if len(data) >= 28:
                    # Secondary address length at offset 24
                    sec_addr_len = struct.unpack("<H", data[24:26])[0]
                    metadata["secondary_addr_len"] = sec_addr_len
                confidence = 85
            else:
                metadata["bind_rejected"] = True
                confidence = 70

            return ServiceIdentity(
                service="opcda",
                certainty=confidence,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _build_dcerpc_bind(self) -> bytes:
        """Build a DCE/RPC bind PDU for IOPCServer interface."""
        # NDR transfer syntax UUID
        ndr_uuid = (
            b"\x04\x5d\x88\x8a\xeb\x1c\xc9\x11"
            b"\x9f\xe8\x08\x00\x2b\x10\x48\x60"
        )
        ndr_version = struct.pack("<HH", 2, 0)

        # Context item: abstract syntax (OPC) + transfer syntax (NDR)
        ctx_item = struct.pack("<HB", 0, 1)  # context_id=0, num_transfer=1
        ctx_item += b"\x00"  # reserved
        ctx_item += _OPC_SERVER_UUID + struct.pack("<HH", 0, 0)  # abstract syntax
        ctx_item += ndr_uuid + ndr_version  # transfer syntax

        # Bind PDU body
        body = struct.pack("<HH", 5840, 5840)  # max xmit/recv frag
        body += struct.pack("<I", 0)            # assoc group
        body += struct.pack("<B", 1) + b"\x00" * 3  # num contexts + padding
        body += ctx_item

        # DCERPC header (16 bytes total)
        frag_length = 16 + len(body)
        header = struct.pack(
            "<BBBB I HH I",
            5,              # version
            0,              # minor version
            11,             # bind (type 11)
            0x03,           # flags: first+last frag
            0x00000010,     # data representation (little endian, ASCII, IEEE)
            frag_length,    # frag length
            0,              # auth length
            1,              # call ID
        )

        return header + body
