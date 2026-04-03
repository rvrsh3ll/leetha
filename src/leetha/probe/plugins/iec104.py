"""IEC 60870-5-104 probe plugin — STARTDT activation and confirmation."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IEC104ProbePlugin(ServiceProbe):
    name = "iec104"
    protocol = "tcp"
    default_ports = [2404]

    # STARTDT Act (Start Data Transfer Activation) U-frame
    # Start byte 0x68, APDU length 4, control field 0x07 0x00 0x00 0x00
    STARTDT_ACT = b"\x68\x04\x07\x00\x00\x00"

    # Expected STARTDT Con (Confirmation) response
    # Start byte 0x68, APDU length 4, control field 0x0B 0x00 0x00 0x00
    STARTDT_CON = b"\x68\x04\x0B\x00\x00\x00"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            conn.write(self.STARTDT_ACT)
            data = conn.read(1024)
            if not data or len(data) < 6:
                return None

            # Validate start byte
            if data[0] != 0x68:
                return None

            apdu_length = data[1]
            if apdu_length < 4:
                return None

            metadata = {
                "apdu_length": apdu_length,
            }

            # Parse control field
            control = data[2:6]
            metadata["control_field"] = control.hex()

            # Check if this is a U-frame (bits 0 and 1 of first control byte)
            ctrl_byte1 = control[0]

            # STARTDT Con: control field byte 0 = 0x0B
            if ctrl_byte1 == 0x0B:
                metadata["frame_type"] = "U-frame"
                metadata["startdt_con"] = True
                return ServiceIdentity(
                    service="iec104",
                    certainty=90,
                    metadata=metadata,
                )

            # STARTDT Act echo (some devices echo back the activation)
            if ctrl_byte1 == 0x07:
                metadata["frame_type"] = "U-frame"
                metadata["startdt_act_echo"] = True
                return ServiceIdentity(
                    service="iec104",
                    certainty=85,
                    metadata=metadata,
                )

            # Any other valid IEC 104 APDU with start byte 0x68
            # Could be S-frame or I-frame
            if ctrl_byte1 & 0x01 == 0:
                metadata["frame_type"] = "I-frame"
            elif ctrl_byte1 & 0x03 == 0x01:
                metadata["frame_type"] = "S-frame"
            else:
                metadata["frame_type"] = "U-frame"

            return ServiceIdentity(
                service="iec104",
                certainty=80,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None
