"""Apache Pulsar probe plugin — binary protocol CommandConnect."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class PulsarProbePlugin(ServiceProbe):
    name = "pulsar"
    protocol = "tcp"
    default_ports = [6650]

    # Pulsar command types (from PulsarApi.proto)
    CMD_CONNECT = 2
    CMD_CONNECTED = 3
    CMD_ERROR = 5

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build a minimal CommandConnect message
            # Pulsar framing: [4-byte total size][4-byte cmd size][serialized cmd]
            # CommandConnect is type 2 with minimal fields:
            #   field 1 (client_version): string "leetha"
            #   field 2 (protocol_version): int32 0
            # Protobuf encoding:
            #   tag 1, wire type 2 (length-delimited): 0x0a
            #   length 5, "leetha"
            #   tag 3, wire type 0 (varint): 0x18, value 0x00
            # BaseCommand wrapper:
            #   tag 1 (type), wire type 0: 0x08, value 2 (CONNECT)
            #   tag 3 (connect), wire type 2: 0x1a, length, CommandConnect bytes

            connect_cmd = b"\x0a\x05leetha\x18\x00"  # CommandConnect
            base_cmd = (
                b"\x08\x02"  # type = CONNECT (2)
                + b"\x1a"
                + bytes([len(connect_cmd)])
                + connect_cmd
            )

            cmd_size = len(base_cmd)
            total_size = 4 + cmd_size  # cmd_size field + command bytes
            frame = struct.pack(">I", total_size) + struct.pack(">I", cmd_size) + base_cmd

            conn.write(frame)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Parse response frame
            total_sz = struct.unpack(">I", data[0:4])[0]
            cmd_sz = struct.unpack(">I", data[4:8])[0]

            if cmd_sz > total_sz or cmd_sz == 0:
                return None

            # Parse the BaseCommand protobuf
            cmd_data = data[8 : 8 + cmd_sz]
            if len(cmd_data) < 2:
                return None

            # Decode type field (tag 1, varint)
            cmd_type = self._decode_type(cmd_data)
            if cmd_type not in (self.CMD_CONNECTED, self.CMD_ERROR):
                return None

            metadata = {"cmd_type": cmd_type}
            version = None

            # Try to extract server version from CommandConnected
            if cmd_type == self.CMD_CONNECTED:
                version = self._extract_version(cmd_data)
                if version:
                    metadata["server_version"] = version

            return ServiceIdentity(
                service="pulsar",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None

    def _decode_type(self, cmd_data: bytes) -> int | None:
        """Decode the type field from BaseCommand protobuf."""
        try:
            i = 0
            while i < len(cmd_data):
                # Read tag
                tag_byte = cmd_data[i]
                field_num = tag_byte >> 3
                wire_type = tag_byte & 0x07
                i += 1

                if field_num == 1 and wire_type == 0:
                    # Varint: read the type value
                    val = 0
                    shift = 0
                    while i < len(cmd_data):
                        b = cmd_data[i]
                        i += 1
                        val |= (b & 0x7F) << shift
                        if not (b & 0x80):
                            break
                        shift += 7
                    return val
                elif wire_type == 0:
                    # Skip varint
                    while i < len(cmd_data) and cmd_data[i] & 0x80:
                        i += 1
                    i += 1
                elif wire_type == 2:
                    # Length-delimited: skip
                    length = 0
                    shift = 0
                    while i < len(cmd_data):
                        b = cmd_data[i]
                        i += 1
                        length |= (b & 0x7F) << shift
                        if not (b & 0x80):
                            break
                        shift += 7
                    i += length
                else:
                    break
        except (IndexError, struct.error):
            pass
        return None

    def _extract_version(self, cmd_data: bytes) -> str | None:
        """Try to extract server_version string from CommandConnected."""
        try:
            # Look for string patterns that look like version numbers
            # CommandConnected has field 1 (server_version) as string
            # In the BaseCommand, CommandConnected is field 4 (tag 0x22)
            i = 0
            while i < len(cmd_data):
                tag_byte = cmd_data[i]
                field_num = tag_byte >> 3
                wire_type = tag_byte & 0x07
                i += 1

                if wire_type == 2:  # length-delimited
                    length = 0
                    shift = 0
                    while i < len(cmd_data):
                        b = cmd_data[i]
                        i += 1
                        length |= (b & 0x7F) << shift
                        if not (b & 0x80):
                            break
                        shift += 7

                    if field_num == 4:  # CommandConnected submessage
                        sub = cmd_data[i : i + length]
                        return self._parse_connected_version(sub)
                    i += length
                elif wire_type == 0:  # varint
                    while i < len(cmd_data) and cmd_data[i] & 0x80:
                        i += 1
                    i += 1
                else:
                    break
        except (IndexError, struct.error):
            pass
        return None

    def _parse_connected_version(self, sub: bytes) -> str | None:
        """Parse server_version from CommandConnected sub-message."""
        try:
            i = 0
            while i < len(sub):
                tag_byte = sub[i]
                field_num = tag_byte >> 3
                wire_type = tag_byte & 0x07
                i += 1

                if wire_type == 2:
                    length = 0
                    shift = 0
                    while i < len(sub):
                        b = sub[i]
                        i += 1
                        length |= (b & 0x7F) << shift
                        if not (b & 0x80):
                            break
                        shift += 7
                    if field_num == 1:  # server_version
                        return sub[i : i + length].decode("utf-8", errors="replace")
                    i += length
                elif wire_type == 0:
                    while i < len(sub) and sub[i] & 0x80:
                        i += 1
                    i += 1
                else:
                    break
        except (IndexError, struct.error):
            pass
        return None
