"""Neo4j Bolt probe plugin — Bolt protocol handshake."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class Neo4jProbePlugin(ServiceProbe):
    name = "neo4j"
    protocol = "tcp"
    default_ports = [7687]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Bolt handshake:
            # Magic preamble (4 bytes) + 4 version proposals (4 bytes each)
            preamble = b"\x60\x60\xB0\x17"
            # Version proposals: range(patch.minor.major.pad)
            # v4.4, v4.3, v4.2, v4.1
            versions = (
                b"\x00\x04\x04\x04"  # v4.4 with range
                b"\x00\x03\x04\x04"  # v4.3 with range
                b"\x00\x02\x04\x04"  # v4.2 with range
                b"\x00\x01\x04\x04"  # v4.1 with range
            )
            conn.write(preamble + versions)
            data = conn.read(4)
            if not data or len(data) < 4:
                return None

            # Server responds with 4-byte selected version
            # All zeros means no agreement
            if data == b"\x00\x00\x00\x00":
                return None

            # Parse version: data[3]=major, data[2]=minor, data[1]=patch
            major = data[3]
            minor = data[2]
            patch = data[1]
            if major == 0:
                return None

            version = f"{major}.{minor}"
            if patch:
                version += f".{patch}"

            metadata: dict = {
                "bolt_version_major": major,
                "bolt_version_minor": minor,
            }
            if patch:
                metadata["bolt_version_patch"] = patch

            return ServiceIdentity(
                service="neo4j",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
