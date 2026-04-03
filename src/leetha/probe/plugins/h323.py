"""H.323 probe plugin — H.225.0 Setup message (Q.931) for VoIP gatekeeper detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class H323ProbePlugin(ServiceProbe):
    name = "h323"
    protocol = "tcp"
    default_ports = [1720]

    # Valid Q.931 response message types
    _VALID_MSG_TYPES = {
        0x01: "ALERTING",
        0x02: "CALL_PROCEEDING",
        0x07: "CONNECT",
        0x4D: "RELEASE_COMPLETE",
        0x45: "DISCONNECT",
        0x05: "SETUP",
        0x0D: "SETUP_ACK",
        0x03: "PROGRESS",
        0x6E: "STATUS",
    }

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal Q.931 SETUP message
            # Protocol discriminator: 0x08 (Q.931)
            # Call reference length: 2
            # Call reference value: 0x0001 (arbitrary)
            # Message type: 0x05 (SETUP)
            # Bearer capability IE (mandatory for SETUP)
            bearer_ie = bytes([
                0x04,        # IE identifier: Bearer capability
                0x03,        # Length
                0x80,        # Coding standard: ITU-T, information transfer capability: speech
                0x90,        # Transfer mode: circuit, rate: 64kbit/s
                0xA3,        # Layer 1: G.711 A-law
            ])

            q931_msg = bytes([
                0x08,        # Protocol discriminator (Q.931)
                0x02,        # Call reference length
                0x00, 0x01,  # Call reference value
                0x05,        # Message type: SETUP
            ]) + bearer_ie

            # TPKT header: version 3, reserved 0, total length
            tpkt_payload_len = 4 + len(q931_msg)
            tpkt = struct.pack(">BBH", 3, 0, tpkt_payload_len)

            conn.write(tpkt + q931_msg)
            data = conn.read(1024)
            if not data or len(data) < 5:
                return None

            # Check for TPKT header (version 3)
            if data[0] != 0x03:
                return None

            # Parse Q.931 message from the response
            # Skip TPKT header (4 bytes)
            q931 = data[4:]
            if len(q931) < 5:
                return None

            # Check protocol discriminator
            proto_disc = q931[0]
            if proto_disc != 0x08:
                return None

            # Parse call reference
            cr_len = q931[1]
            if len(q931) < 2 + cr_len + 1:
                return None

            # Get message type
            msg_type = q931[2 + cr_len]

            metadata: dict = {
                "protocol_discriminator": proto_disc,
                "call_reference_length": cr_len,
                "message_type": msg_type,
            }

            if msg_type in self._VALID_MSG_TYPES:
                metadata["message_type_name"] = self._VALID_MSG_TYPES[msg_type]

            return ServiceIdentity(
                service="h323",
                certainty=80,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
