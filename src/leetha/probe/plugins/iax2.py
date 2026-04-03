"""IAX2 probe plugin — IAX2 POKE frame for Asterisk PBX detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IAX2ProbePlugin(ServiceProbe):
    name = "iax2"
    protocol = "udp"
    default_ports = [4569]

    # IAX2 frame type and subclass constants
    _FRAMETYPE_IAX = 0x06
    _SUBCLASS_POKE = 0x1E
    _SUBCLASS_PONG = 0x03

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build IAX2 Full Frame (POKE)
            # F bit (1) + Source call number (15 bits)
            # R bit (0) + Destination call number (15 bits)
            # Timestamp (4 bytes)
            # OSeqno (1 byte)
            # ISeqno (1 byte)
            # Frame type (1 byte)
            # Subclass (1 byte) — C bit clear, so subclass is 7 bits

            source_call = 0x0002  # Arbitrary source call number
            dest_call = 0x0000    # No dest call yet (new call)

            frame = struct.pack(">H", 0x8000 | source_call)  # F=1 + source call
            frame += struct.pack(">H", dest_call)             # R=0 + dest call
            frame += struct.pack(">I", 0)                     # Timestamp
            frame += struct.pack("B", 0)                      # OSeqno
            frame += struct.pack("B", 0)                      # ISeqno
            frame += struct.pack("B", self._FRAMETYPE_IAX)    # Frame type: IAX
            frame += struct.pack("B", self._SUBCLASS_POKE)    # Subclass: POKE

            conn.write(frame)
            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            # Parse response: check it's a full frame (F bit set)
            first_word = struct.unpack(">H", data[0:2])[0]
            if not (first_word & 0x8000):
                return None

            # Extract frame type and subclass
            frametype = data[10]
            subclass = data[11]

            metadata: dict = {
                "frametype": frametype,
                "subclass": subclass,
            }

            # Check for PONG response (IAX frame type, PONG subclass)
            if frametype == self._FRAMETYPE_IAX and subclass == self._SUBCLASS_PONG:
                metadata["response"] = "PONG"
                return ServiceIdentity(
                    service="iax2",
                    certainty=85,
                    metadata=metadata,
                )

            # Any IAX frame type response still indicates IAX2 service
            if frametype == self._FRAMETYPE_IAX:
                metadata["response"] = f"IAX_subclass_{subclass}"
                return ServiceIdentity(
                    service="iax2",
                    certainty=70,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
