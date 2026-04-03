"""OMRON FINS probe plugin — Node Address Data Send command over UDP."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class FINSProbePlugin(ServiceProbe):
    name = "fins"
    protocol = "udp"
    default_ports = [9600]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # FINS Header
            # ICF: 0x80 (Command, needs response, from gateway)
            # RSV: 0x00 (Reserved)
            # GCT: 0x02 (Gateway count, max 2 hops)
            # DNA: 0x00 (Destination network address, local)
            # DA1: 0x00 (Destination node address, auto)
            # DA2: 0x00 (Destination unit address, CPU)
            # SNA: 0x00 (Source network address, local)
            # SA1: 0x00 (Source node address, auto)
            # SA2: 0x00 (Source unit address)
            # SID: 0x01 (Service ID)
            header = bytes([
                0x80,   # ICF: command, need response
                0x00,   # RSV
                0x02,   # GCT
                0x00,   # DNA
                0x00,   # DA1
                0x00,   # DA2
                0x00,   # SNA
                0x00,   # SA1
                0x00,   # SA2
                0x01,   # SID
            ])

            # Command: Read Controller Data (0x05 0x01)
            command = struct.pack(">BB", 0x05, 0x01)

            request = header + command

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            # Validate FINS response
            # ICF byte should have response bit (bit 6) set: ICF & 0x40 != 0
            icf = data[0]
            if not (icf & 0x40):
                return None

            metadata = {
                "icf": icf,
                "rsv": data[1],
                "gct": data[2],
                "dna": data[3],
                "da1": data[4],
                "da2": data[5],
                "sna": data[6],
                "sa1": data[7],
                "sa2": data[8],
                "sid": data[9],
            }

            # Parse command code from response
            if len(data) >= 12:
                resp_cmd = struct.unpack(">BB", data[10:12])
                metadata["response_command"] = f"0x{resp_cmd[0]:02X}{resp_cmd[1]:02X}"

            # Parse end code (response status)
            if len(data) >= 14:
                end_code = struct.unpack(">H", data[12:14])[0]
                metadata["end_code"] = end_code

            # Parse controller data if available
            if len(data) > 14:
                self._parse_controller_data(data[14:], metadata)

            version = metadata.get("model")
            return ServiceIdentity(
                service="fins",
                certainty=85,
                version=version,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_controller_data(self, payload: bytes, metadata: dict) -> None:
        """Parse controller data from FINS response payload."""
        try:
            # Controller model (20 bytes ASCII, padded)
            if len(payload) >= 20:
                model = payload[0:20].decode("ascii", errors="replace").rstrip(
                    "\x00 "
                )
                if model:
                    metadata["model"] = model

            # Controller version (20 bytes ASCII, padded)
            if len(payload) >= 40:
                version = payload[20:40].decode("ascii", errors="replace").rstrip(
                    "\x00 "
                )
                if version:
                    metadata["controller_version"] = version
        except (IndexError, struct.error):
            pass
