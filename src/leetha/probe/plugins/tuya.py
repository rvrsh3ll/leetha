"""Tuya protocol probe plugin — v3.3 heartbeat detection."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TuyaProbePlugin(ServiceProbe):
    name = "tuya"
    protocol = "tcp"
    default_ports = [6668]

    # Tuya magic constants
    _PREFIX = 0x000055AA
    _SUFFIX = 0x0000AA55

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build Tuya v3.3 heartbeat packet
            # Format: prefix(4) + seqno(4) + cmd(4) + payload_len(4) + payload + crc(4) + suffix(4)
            cmd = 0x09  # HEARTBEAT command (some devices use 0x0a)
            payload = b""
            # Calculate total data length: payload + return_code(4) + crc(4) + suffix(4)
            data_len = len(payload) + 12

            packet = struct.pack(">I", self._PREFIX)    # magic prefix
            packet += struct.pack(">I", 1)              # sequence number
            packet += struct.pack(">I", cmd)             # command
            packet += struct.pack(">I", data_len)        # data length
            # return code
            packet += struct.pack(">I", 0)
            # CRC32 placeholder (Tuya doesn't always validate)
            packet += struct.pack(">I", 0x00000000)
            # Suffix
            packet += struct.pack(">I", self._SUFFIX)

            conn.write(packet)
            data = conn.read(4096)

            if not data or len(data) < 16:
                return None

            # Check for Tuya magic prefix
            if len(data) < 4:
                return None

            prefix = struct.unpack(">I", data[:4])[0]
            if prefix != self._PREFIX:
                return None

            metadata: dict = {"raw_length": len(data)}

            # Parse response header if enough data
            if len(data) >= 16:
                seq = struct.unpack(">I", data[4:8])[0]
                resp_cmd = struct.unpack(">I", data[8:12])[0]
                resp_len = struct.unpack(">I", data[12:16])[0]
                metadata["response_cmd"] = resp_cmd
                metadata["sequence"] = seq
                metadata["data_length"] = resp_len

            # Check for suffix
            if len(data) >= 8:
                suffix = struct.unpack(">I", data[-4:])[0]
                if suffix == self._SUFFIX:
                    metadata["valid_suffix"] = True

            return ServiceIdentity(
                service="tuya",
                certainty=85,
                version="3.3",
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
