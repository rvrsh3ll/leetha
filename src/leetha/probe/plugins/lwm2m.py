"""LwM2M probe plugin — OMA Lightweight M2M over CoAP."""
from __future__ import annotations

import os
import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class LwM2MProbePlugin(ServiceProbe):
    name = "lwm2m"
    protocol = "udp"
    default_ports = [5684]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build CoAP GET /rd (LwM2M registration endpoint)
            token = os.urandom(2)
            msg_id = struct.pack("!H", 0x0001)

            header = bytes([
                0x42,   # Ver=1, Type=CON, TKL=2
                0x01,   # Code: 0.01 = GET
            ])
            header += msg_id + token

            # Option: Uri-Path = "rd" (option delta 11, length 2)
            opt = bytes([0xB2]) + b"rd"

            packet = header + opt
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

            # Accept success (2.xx) or client error (4.xx) responses
            if code_class not in (2, 4):
                return None

            metadata: dict = {
                "code": f"{code_class}.{code_detail:02d}",
            }

            # Try to extract payload
            payload_marker = data.find(b"\xff")
            banner = None
            is_lwm2m = False
            if payload_marker != -1:
                payload = data[payload_marker + 1:]
                banner = payload.decode("utf-8", errors="replace")[:512]
                metadata["payload_length"] = len(payload)
                # Check for LwM2M indicators in payload
                lower = banner.lower()
                if "lwm2m" in lower or "registration" in lower or "rd" in lower:
                    is_lwm2m = True
                    metadata["lwm2m_detected"] = True

            # Even without LwM2M payload, a valid CoAP response on 5684
            # to /rd is a strong indicator
            confidence = 80 if is_lwm2m else 65

            return ServiceIdentity(
                service="lwm2m",
                certainty=confidence,
                metadata=metadata,
                banner=banner,
            )
        except (socket.timeout, OSError):
            return None
