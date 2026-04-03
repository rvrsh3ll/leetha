"""Fluentd probe plugin — send Fluentd forward protocol message and check for ack."""
from __future__ import annotations
import json
import socket
import struct
import time
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FluentdProbePlugin(ServiceProbe):
    name = "fluentd"
    protocol = "tcp"
    default_ports = [24224]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal Fluentd forward protocol message using msgpack
            # Format: [tag, time, record, option]
            # We use a minimal msgpack encoding
            tag = b"probe.test"
            ts = int(time.time())
            chunk_id = b"leetha_probe_chunk"

            # Msgpack: fixarray(4) + fixstr(tag) + uint32(time) + fixmap(1){fixstr("msg"):fixstr("probe")} + fixmap(1){fixstr("chunk"):fixstr(chunk_id)}
            msg = self._encode_forward_message(tag, ts, chunk_id)
            conn.write(msg)

            # Set a short timeout for the ack
            conn.set_timeout(3)
            data = conn.read(4096)
            if not data:
                return None

            # Fluentd ack response is msgpack: {"ack": chunk_id}
            # Look for the chunk_id in the response as a heuristic
            response = data.decode("utf-8", errors="replace")
            metadata: dict = {"protocol": "forward"}

            if chunk_id.decode() in response or b"ack" in data:
                metadata["ack_received"] = True
                return ServiceIdentity(
                    service="fluentd",
                    certainty=85,
                    metadata=metadata,
                )

            # Even without ack, if we got a structured response it may be Fluentd
            if len(data) >= 2:
                metadata["ack_received"] = False
                return ServiceIdentity(
                    service="fluentd",
                    certainty=60,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError):
            return None

    @staticmethod
    def _encode_forward_message(tag: bytes, ts: int, chunk_id: bytes) -> bytes:
        """Encode a minimal Fluentd forward protocol message in msgpack format."""
        # fixarray of 4 elements: 0x94
        msg = b"\x94"
        # fixstr for tag
        msg += bytes([0xa0 | len(tag)]) + tag
        # uint32 for timestamp
        msg += b"\xce" + struct.pack(">I", ts)
        # fixmap(1) for record: {"msg": "probe"}
        msg += b"\x81"
        msg += b"\xa3msg"
        msg += b"\xa5probe"
        # fixmap(1) for options: {"chunk": chunk_id}
        msg += b"\x81"
        msg += b"\xa5chunk"
        msg += bytes([0xa0 | len(chunk_id)]) + chunk_id
        return msg
