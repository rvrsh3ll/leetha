"""CoAP probe plugin — RFC 7252 Constrained Application Protocol."""
from __future__ import annotations

import os
import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CoAPProbePlugin(ServiceProbe):
    name = "coap"
    protocol = "udp"
    default_ports = [5683]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build CoAP GET /.well-known/core
            # Ver=1, Type=CON(0), Token Length=2, Code=GET(0.01)
            token = os.urandom(2)
            msg_id = struct.pack("!H", 0x0001)

            # Header: VV TT TTTT CCCC CCCC  (V=01, T=00 CON, TKL=0010)
            header = bytes([
                0x42,   # Ver=1(01), Type=CON(00), TKL=2(0010)
                0x01,   # Code: 0.01 = GET
            ])
            header += msg_id + token

            # Option: Uri-Path = ".well-known" (option delta 11, length 11)
            # Option number 11 (Uri-Path), delta=11, length=11
            well_known = b".well-known"
            opt1 = bytes([0xBB]) + well_known  # delta=11, length=11

            # Option: Uri-Path = "core" (option delta 0, length 4)
            core = b"core"
            opt2 = bytes([0x04]) + core  # delta=0, length=4

            packet = header + opt1 + opt2
            conn.write(packet)
            data = conn.read(4096)

            if not data or len(data) < 4:
                return None

            # Parse CoAP response header
            first_byte = data[0]
            ver = (first_byte >> 6) & 0x03
            if ver != 1:
                return None

            code_byte = data[1]
            code_class = (code_byte >> 5) & 0x07
            code_detail = code_byte & 0x1F

            # Accept 2.xx success responses (class 2) or 4.xx client errors
            if code_class not in (2, 4):
                return None

            tkl = first_byte & 0x0F
            metadata: dict = {
                "code": f"{code_class}.{code_detail:02d}",
                "version": ver,
            }

            # Try to extract payload (after 0xFF marker)
            payload_marker = data.find(b"\xff")
            banner = None
            if payload_marker != -1:
                payload = data[payload_marker + 1:]
                banner = payload.decode("utf-8", errors="replace")[:512]
                metadata["payload_length"] = len(payload)

            confidence = 85 if code_class == 2 else 70

            return ServiceIdentity(
                service="coap",
                certainty=confidence,
                metadata=metadata,
                banner=banner,
            )
        except (socket.timeout, OSError):
            return None
