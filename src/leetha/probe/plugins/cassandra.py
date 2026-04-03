"""Cassandra probe plugin — CQL native protocol OPTIONS request."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class CassandraProbePlugin(ServiceProbe):
    name = "cassandra"
    protocol = "tcp"
    default_ports = [9042, 9142]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # CQL v4 OPTIONS request
            # version(1)=0x04 + flags(1)=0x00 + stream(2)=0x0000 +
            # opcode(1)=0x05(OPTIONS) + length(4)=0x00000000
            options_req = b"\x04\x00\x00\x00\x05\x00\x00\x00\x00"
            conn.write(options_req)
            data = conn.read(4096)
            if not data or len(data) < 9:
                return None

            # Parse CQL response frame header
            resp_version = data[0]
            resp_opcode = data[4]

            # Check for SUPPORTED response (opcode 0x06)
            if resp_opcode != 0x06:
                return None

            body_len = struct.unpack(">I", data[5:9])[0]
            body = data[9:9 + body_len]

            metadata: dict = {"cql_version_byte": resp_version & 0x7F}
            version = None

            # Parse string multimap from body
            options = self._parse_string_multimap(body)
            if options:
                metadata["options"] = options
                if "CQL_VERSION" in options:
                    cql_versions = options["CQL_VERSION"]
                    if cql_versions:
                        version = cql_versions[0]
                        metadata["cql_versions"] = cql_versions
                if "COMPRESSION" in options:
                    metadata["compression"] = options["COMPRESSION"]

            return ServiceIdentity(
                service="cassandra",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None

    @staticmethod
    def _parse_string_multimap(data: bytes) -> dict[str, list[str]]:
        """Parse CQL string multimap: {key: [value, ...], ...}."""
        result: dict[str, list[str]] = {}
        try:
            offset = 0
            if len(data) < 2:
                return result
            n_keys = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            for _ in range(n_keys):
                if offset + 2 > len(data):
                    break
                key_len = struct.unpack(">H", data[offset:offset + 2])[0]
                offset += 2
                key = data[offset:offset + key_len].decode("utf-8", errors="replace")
                offset += key_len
                if offset + 2 > len(data):
                    break
                n_values = struct.unpack(">H", data[offset:offset + 2])[0]
                offset += 2
                values = []
                for _ in range(n_values):
                    if offset + 2 > len(data):
                        break
                    val_len = struct.unpack(">H", data[offset:offset + 2])[0]
                    offset += 2
                    val = data[offset:offset + val_len].decode("utf-8", errors="replace")
                    offset += val_len
                    values.append(val)
                result[key] = values
        except Exception:
            pass
        return result
