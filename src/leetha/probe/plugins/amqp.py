"""AMQP probe plugin — protocol header exchange."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class AMQPProbePlugin(ServiceProbe):
    name = "amqp"
    protocol = "tcp"
    default_ports = [5672, 5671]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send AMQP 0-9-1 protocol header
            conn.write(b"AMQP\x00\x00\x09\x01")
            data = conn.read(4096)
            if not data or len(data) < 7:
                return None

            # Check for AMQP protocol header reply (version negotiation)
            if data[:4] == b"AMQP":
                version = f"{data[5]}.{data[6]}.{data[7]}" if len(data) >= 8 else None
                return ServiceIdentity(
                    service="amqp",
                    certainty=90,
                    version=version,
                    metadata={"negotiation": True},
                )

            # Check for Connection.Start method frame
            # Frame type 1 (method), channel 0, then payload
            if len(data) < 11:
                return None

            frame_type = data[0]
            channel = struct.unpack(">H", data[1:3])[0]
            payload_size = struct.unpack(">I", data[3:7])[0]

            if frame_type != 1 or channel != 0:
                return None

            # Payload starts at offset 7
            if len(data) < 7 + 4:
                return None

            class_id = struct.unpack(">H", data[7:9])[0]
            method_id = struct.unpack(">H", data[9:11])[0]

            # Connection.Start: class 10, method 10
            if class_id != 10 or method_id != 10:
                return None

            metadata = {}
            version = None

            # Parse version-major, version-minor (bytes 11, 12)
            if len(data) >= 13:
                version_major = data[11]
                version_minor = data[12]
                version = f"{version_major}.{version_minor}"

            # Try to extract server-properties from the frame
            # After version bytes, there's a server-properties field table
            if len(data) > 13:
                product, ver = self._parse_server_properties(data, 13)
                if product:
                    metadata["product"] = product
                if ver:
                    metadata["server_version"] = ver

            return ServiceIdentity(
                service="amqp",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None

    def _parse_server_properties(self, data: bytes, offset: int) -> tuple[str | None, str | None]:
        """Try to extract product and version from AMQP server-properties field table."""
        product = None
        version = None
        try:
            if offset + 4 > len(data):
                return None, None
            table_size = struct.unpack(">I", data[offset:offset + 4])[0]
            offset += 4
            end = offset + table_size
            if end > len(data):
                end = len(data)

            while offset < end - 3:
                # Field name: short string (1-byte length + data)
                name_len = data[offset]
                offset += 1
                if offset + name_len > end:
                    break
                field_name = data[offset:offset + name_len].decode("utf-8", errors="replace")
                offset += name_len

                if offset >= end:
                    break

                # Field value type
                field_type = chr(data[offset])
                offset += 1

                if field_type == "S":  # long string
                    if offset + 4 > end:
                        break
                    val_len = struct.unpack(">I", data[offset:offset + 4])[0]
                    offset += 4
                    if offset + val_len > end:
                        break
                    val = data[offset:offset + val_len].decode("utf-8", errors="replace")
                    offset += val_len

                    if field_name.lower() == "product":
                        product = val
                    elif field_name.lower() == "version":
                        version = val
                elif field_type == "F":  # nested table
                    if offset + 4 > end:
                        break
                    nested_size = struct.unpack(">I", data[offset:offset + 4])[0]
                    offset += 4 + nested_size
                elif field_type == "t":  # boolean
                    offset += 1
                elif field_type in ("b", 'B'):  # short-short-int
                    offset += 1
                elif field_type in ("s', 'u"):  # short-int
                    offset += 2
                elif field_type in ("I", "i"):  # long-int
                    offset += 4
                elif field_type in ("l", "L"):  # long-long-int
                    offset += 8
                else:
                    # Unknown type, bail out
                    break
        except (struct.error, IndexError, UnicodeDecodeError):
            pass
        return product, version
