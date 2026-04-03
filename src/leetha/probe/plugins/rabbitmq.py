"""RabbitMQ probe plugin — identifies RabbitMQ via AMQP server-properties."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class RabbitMQProbePlugin(ServiceProbe):
    name = "rabbitmq"
    protocol = "tcp"
    default_ports = [5672]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send AMQP 0-9-1 protocol header
            conn.write(b"AMQP\x00\x00\x09\x01")
            data = conn.read(8192)
            if not data or len(data) < 11:
                return None

            # Must be a method frame (type 1), channel 0
            frame_type = data[0]
            channel = struct.unpack(">H", data[1:3])[0]
            if frame_type != 1 or channel != 0:
                return None

            # Connection.Start: class 10, method 10
            class_id = struct.unpack(">H", data[7:9])[0]
            method_id = struct.unpack(">H", data[9:11])[0]
            if class_id != 10 or method_id != 10:
                return None

            # Parse server-properties field table starting at offset 13
            # (after version-major and version-minor at bytes 11-12)
            if len(data) < 14:
                return None

            product, version = self._parse_server_properties(data, 13)

            # Only match if this is specifically RabbitMQ
            if not product or "RabbitMQ" not in product:
                return None

            metadata = {"product": product}
            if version:
                metadata["server_version"] = version

            return ServiceIdentity(
                service="rabbitmq",
                certainty=95,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None

    def _parse_server_properties(
        self, data: bytes, offset: int
    ) -> tuple[str | None, str | None]:
        """Extract product and version from AMQP server-properties field table."""
        product = None
        version = None
        try:
            if offset + 4 > len(data):
                return None, None
            table_size = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4
            end = offset + table_size
            if end > len(data):
                end = len(data)

            while offset < end - 3:
                # Field name: 1-byte length + data
                name_len = data[offset]
                offset += 1
                if offset + name_len > end:
                    break
                field_name = data[offset : offset + name_len].decode(
                    "utf-8", errors="replace"
                )
                offset += name_len

                if offset >= end:
                    break

                field_type = chr(data[offset])
                offset += 1

                if field_type == "S":  # long string
                    if offset + 4 > end:
                        break
                    val_len = struct.unpack(">I", data[offset : offset + 4])[0]
                    offset += 4
                    if offset + val_len > end:
                        break
                    val = data[offset : offset + val_len].decode(
                        "utf-8", errors="replace"
                    )
                    offset += val_len

                    if field_name.lower() == "product":
                        product = val
                    elif field_name.lower() == "version":
                        version = val
                elif field_type == "F":  # nested table
                    if offset + 4 > end:
                        break
                    nested_size = struct.unpack(">I", data[offset : offset + 4])[0]
                    offset += 4 + nested_size
                elif field_type == "t":  # boolean
                    offset += 1
                elif field_type in ("b", "B"):  # short-short-int
                    offset += 1
                elif field_type in ("s", "u"):  # short-int
                    offset += 2
                elif field_type in ("I", "i"):  # long-int
                    offset += 4
                elif field_type in ("l", "L"):  # long-long-int
                    offset += 8
                else:
                    break
        except (struct.error, IndexError, UnicodeDecodeError):
            pass
        return product, version
