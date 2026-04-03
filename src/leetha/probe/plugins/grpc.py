"""gRPC probe plugin — HTTP/2 connection preface detection."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GRPCProbePlugin(ServiceProbe):
    name = "grpc"
    protocol = "tcp"
    default_ports = [50051]

    # HTTP/2 connection preface
    H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    # Frame types
    FRAME_SETTINGS = 0x04
    FRAME_GOAWAY = 0x07

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send HTTP/2 connection preface followed by an empty SETTINGS frame
            # SETTINGS frame: length(3) + type(1) + flags(1) + stream_id(4)
            settings_frame = struct.pack(">I", 0)[1:]  # 3-byte length = 0
            settings_frame += bytes([self.FRAME_SETTINGS])  # type
            settings_frame += bytes([0])  # flags
            settings_frame += struct.pack(">I", 0)  # stream ID 0

            conn.write(self.H2_PREFACE + settings_frame)
            data = conn.read(4096)
            if not data or len(data) < 9:
                return None

            metadata = {}
            version = None

            # Check if response starts with HTTP/2 SETTINGS frame
            # or a GOAWAY frame (which also confirms HTTP/2)
            offset = 0
            found_h2 = False

            while offset + 9 <= len(data):
                # Parse frame header: 3-byte length, 1-byte type, 1-byte flags, 4-byte stream_id
                frame_len = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]
                frame_type = data[offset + 3]
                frame_flags = data[offset + 4]
                stream_id = struct.unpack(">I", data[offset + 5 : offset + 9])[0] & 0x7FFFFFFF

                if frame_type == self.FRAME_SETTINGS:
                    found_h2 = True
                    metadata["settings_frame"] = True
                    # Parse settings pairs (6 bytes each: 2-byte id + 4-byte value)
                    settings = {}
                    s_offset = offset + 9
                    for _ in range(frame_len // 6):
                        if s_offset + 6 > len(data):
                            break
                        s_id = struct.unpack(">H", data[s_offset : s_offset + 2])[0]
                        s_val = struct.unpack(">I", data[s_offset + 2 : s_offset + 6])[0]
                        settings[s_id] = s_val
                        s_offset += 6
                    if settings:
                        metadata["settings"] = settings
                elif frame_type == self.FRAME_GOAWAY:
                    found_h2 = True
                    metadata["goaway"] = True

                offset += 9 + frame_len
                if offset > len(data):
                    break

            if not found_h2:
                return None

            version = "HTTP/2"
            metadata["protocol"] = "h2"

            return ServiceIdentity(
                service="grpc",
                certainty=80,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
