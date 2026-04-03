"""Kafka probe plugin — ApiVersions request."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class KafkaProbePlugin(ServiceProbe):
    name = "kafka"
    protocol = "tcp"
    default_ports = [9092, 9093]

    CORRELATION_ID = 0x706F6E67  # "pong"

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = self._build_api_versions_request()
            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Response: size(4) + correlation_id(4) + error_code(2) + ...
            resp_size = struct.unpack(">i", data[0:4])[0]
            correlation_id = struct.unpack(">i", data[4:8])[0]

            if correlation_id != self.CORRELATION_ID:
                return None

            metadata = {}

            # Parse error code and api versions
            if len(data) >= 10:
                error_code = struct.unpack(">h", data[8:10])[0]
                metadata["error_code"] = error_code

                # Parse API versions array
                if len(data) >= 14 and error_code == 0:
                    api_count = struct.unpack(">i", data[10:14])[0]
                    metadata["api_count"] = api_count
                    apis = []
                    offset = 14
                    for _ in range(min(api_count, 100)):
                        if offset + 6 > len(data):
                            break
                        api_key = struct.unpack(">h", data[offset:offset + 2])[0]
                        min_ver = struct.unpack(">h", data[offset + 2:offset + 4])[0]
                        max_ver = struct.unpack(">h", data[offset + 4:offset + 6])[0]
                        apis.append({"api_key": api_key, "min_version": min_ver, "max_version": max_ver})
                        offset += 6
                    if apis:
                        metadata["api_versions"] = apis

            return ServiceIdentity(
                service="kafka",
                certainty=85,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None

    def _build_api_versions_request(self) -> bytes:
        """Build an ApiVersions (key=18) v0 request."""
        # Header: api_key(2) + api_version(2) + correlation_id(4) + client_id(string)
        api_key = struct.pack(">h", 18)
        api_version = struct.pack(">h", 0)
        correlation_id = struct.pack(">i", self.CORRELATION_ID)
        client_id = b"leetha"
        client_id_field = struct.pack(">h", len(client_id)) + client_id

        payload = api_key + api_version + correlation_id + client_id_field
        size = struct.pack(">i", len(payload))
        return size + payload
