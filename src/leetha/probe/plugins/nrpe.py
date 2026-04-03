"""NRPE probe plugin — send NRPE v2 query packet and check for response header."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class NRPEProbePlugin(ServiceProbe):
    name = "nrpe"
    protocol = "tcp"
    default_ports = [5666]

    # NRPE packet constants
    _NRPE_QUERY = 1
    _NRPE_RESPONSE = 2
    _NRPE_VERSION_2 = 2
    _NRPE_PACKET_SIZE = 1036  # Standard NRPE packet size

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build NRPE v2 query packet
            # Format: version(2) + type(2) + crc32(4) + result_code(2) + buffer(1024) + padding(2)
            packet = struct.pack(">HH", self._NRPE_VERSION_2, self._NRPE_QUERY)
            packet += struct.pack(">I", 0)  # CRC32 placeholder
            packet += struct.pack(">H", 0)  # result code
            # Command buffer: "_NRPE_CHECK" null-padded to 1024 bytes
            command = b"_NRPE_CHECK"
            buffer_data = command + b"\x00" * (1024 - len(command))
            packet += buffer_data
            packet += b"\x00\x00"  # padding

            # Calculate CRC32 and update
            import binascii
            crc = binascii.crc32(packet) & 0xFFFFFFFF
            packet = packet[:4] + struct.pack(">I", crc) + packet[8:]

            conn.write(packet)
            data = conn.read(self._NRPE_PACKET_SIZE + 64)
            if not data or len(data) < 10:
                return None

            # Parse NRPE response header
            if len(data) >= 4:
                resp_version, resp_type = struct.unpack(">HH", data[:4])
            else:
                return None

            # Validate: version should be 2 or 3, type should be RESPONSE(2)
            if resp_version not in (2, 3) or resp_type != self._NRPE_RESPONSE:
                return None

            metadata: dict = {
                "nrpe_version": resp_version,
            }
            version = None

            # Try to extract result text from buffer
            if len(data) >= 10:
                result_code = struct.unpack(">H", data[8:10])[0]
                metadata["result_code"] = result_code

            if len(data) >= 34:
                # Buffer starts at offset 10
                buffer_bytes = data[10:min(len(data), 1034)]
                null_pos = buffer_bytes.find(b"\x00")
                if null_pos > 0:
                    output = buffer_bytes[:null_pos].decode("utf-8", errors="replace")
                    metadata["output"] = output
                    # NRPE version string often in output like "NRPE v4.1.0"
                    if "NRPE" in output:
                        for token in output.split():
                            if token.startswith("v") and "." in token:
                                version = token.lstrip("v")
                                break

            return ServiceIdentity(
                service="nrpe",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
