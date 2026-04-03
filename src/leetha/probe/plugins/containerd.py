"""Containerd probe plugin — gRPC health check with raw bytes to detect containerd."""
from __future__ import annotations

import struct
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ContainerdProbePlugin(ServiceProbe):
    name = "containerd"
    protocol = "tcp"
    default_ports = [10010]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # gRPC uses HTTP/2 framing. We send:
            # 1. HTTP/2 client preface (magic + SETTINGS frame)
            # 2. A HEADERS frame with gRPC health check path

            # HTTP/2 connection preface
            preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

            # SETTINGS frame (type=0x04, flags=0, stream=0, empty payload)
            settings_frame = struct.pack(">I", 0)[1:]  # length = 0 (3 bytes)
            settings_frame += bytes([0x04])  # type = SETTINGS
            settings_frame += bytes([0x00])  # flags
            settings_frame += struct.pack(">I", 0)  # stream ID = 0

            conn.write(preface + settings_frame)
            data = conn.read(4096)
            if not data:
                return None

            resp = data.decode("utf-8", errors="replace")

            # gRPC/HTTP2 server should respond with HTTP/2 frames.
            # Check for known containerd/gRPC patterns
            is_grpc = (
                data[:24] == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                or data[0:3] == b"\x00\x00"  # HTTP/2 frame
                or b"grpc" in data.lower()
                or b"containerd" in data.lower()
            )

            # Also detect HTTP/2 SETTINGS frame response (starts with 0x00 0x00 ... 0x04)
            if len(data) >= 9:
                frame_type = data[3]
                if frame_type == 0x04:  # SETTINGS
                    is_grpc = True

            if not is_grpc:
                return None

            metadata: dict = {}

            if b"containerd" in data.lower():
                metadata["confirmed_containerd"] = True

            # Check if we got a valid HTTP/2 SETTINGS frame back
            if len(data) >= 9 and data[3] == 0x04:
                metadata["http2_settings"] = True

            return ServiceIdentity(
                service="containerd",
                certainty=70,
                version=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
