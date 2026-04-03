"""Foundation Fieldbus HSE probe plugin — SM_Find request over UDP."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FFHSEProbePlugin(ServiceProbe):
    name = "ff_hse"
    protocol = "udp"
    default_ports = [1090, 1091]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # SM_Find request
            # version(1)=0x01, type(1)=0x01 (SM_Find), length(2)=0, transaction_id(4)
            transaction_id = 0x00000001
            request = struct.pack(">BBH I", 0x01, 0x01, 0, transaction_id)

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Parse SM_Find_Reply header
            version, msg_type, body_length = struct.unpack(">BBH", data[0:4])
            tid = struct.unpack(">I", data[4:8])[0]

            # Validate: version must be 0x01, type must be 0x02 (SM_Find_Reply)
            if version != 0x01 or msg_type != 0x02:
                return None

            metadata = {
                "version": version,
                "msg_type": msg_type,
                "transaction_id": tid,
            }

            # Parse device ID block after the header (8 bytes)
            payload = data[8:]
            self._parse_device_id(payload, metadata)

            return ServiceIdentity(
                service="ff_hse",
                certainty=85,
                version=metadata.get("device_tag"),
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_device_id(self, payload: bytes, metadata: dict) -> None:
        """Parse device ID block: manufacturer_id(2) + device_tag(32)."""
        try:
            if len(payload) >= 2:
                manufacturer_id = struct.unpack(">H", payload[0:2])[0]
                metadata["manufacturer_id"] = manufacturer_id

            if len(payload) >= 34:
                device_tag = payload[2:34].decode("ascii", errors="replace").rstrip("\x00 ")
                if device_tag:
                    metadata["device_tag"] = device_tag
        except (IndexError, struct.error):
            pass
