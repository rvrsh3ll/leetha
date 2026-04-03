"""Mumble probe plugin — version packet detection."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MumbleProbePlugin(ServiceProbe):
    name = "mumble"
    protocol = "tcp"
    default_ports = [64738]

    # Mumble message types
    MSG_VERSION = 0

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send Mumble Version message
            # Format: [2-byte type][4-byte length][payload]
            # Version payload: [4-byte version][8-byte release string length prefix + data]
            # Minimal version packet with version 1.3.0 (0x00010300)
            version_payload = struct.pack(">I", 0x00010300)  # version 1.3.0
            # Add OS and OS version as empty strings (protobuf-like)
            # release: tag 2, wire type 2 (length-delimited)
            release_str = b"leetha"
            # Protobuf: field 2 (release), length-delimited
            proto_payload = (
                b"\x08"  # field 1 (version), varint
                + b"\x80\xa6\x04"  # 0x00010300 as varint = 66560
            )

            msg_type = struct.pack(">H", self.MSG_VERSION)
            msg_length = struct.pack(">I", len(version_payload))
            message = msg_type + msg_length + version_payload

            conn.write(message)
            data = conn.read(4096)
            if not data or len(data) < 6:
                return None

            # Parse response header
            resp_type = struct.unpack(">H", data[0:2])[0]
            resp_length = struct.unpack(">I", data[2:6])[0]

            # We expect a Version message back (type 0)
            if resp_type != self.MSG_VERSION:
                return None

            metadata = {}
            version = None

            # Parse version payload
            payload = data[6 : 6 + resp_length]
            if len(payload) >= 4:
                ver_packed = struct.unpack(">I", payload[0:4])[0]
                major = (ver_packed >> 16) & 0xFF
                minor = (ver_packed >> 8) & 0xFF
                patch = ver_packed & 0xFF
                version = f"{major}.{minor}.{patch}"
                metadata["version_raw"] = ver_packed

            # Try to extract release string and OS info from remaining payload
            if len(payload) > 4:
                remaining = payload[4:]
                try:
                    # Release string is typically a length-prefixed string
                    parts = self._parse_strings(remaining)
                    if len(parts) >= 1 and parts[0]:
                        metadata["release"] = parts[0]
                    if len(parts) >= 2 and parts[1]:
                        metadata["os"] = parts[1]
                    if len(parts) >= 3 and parts[2]:
                        metadata["os_version"] = parts[2]
                except Exception:
                    pass

            return ServiceIdentity(
                service="mumble",
                certainty=85,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None

    def _parse_strings(self, data: bytes) -> list[str]:
        """Parse length-prefixed strings from Mumble version payload."""
        strings = []
        offset = 0
        while offset + 4 <= len(data) and len(strings) < 3:
            str_len = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4
            if str_len > 256 or offset + str_len > len(data):
                break
            s = data[offset : offset + str_len].decode("utf-8", errors="replace")
            strings.append(s)
            offset += str_len
        return strings
