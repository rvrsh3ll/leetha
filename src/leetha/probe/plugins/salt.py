"""Salt (SaltStack) probe plugin — ZeroMQ greeting on ret conn.port for Salt Master detection."""
from __future__ import annotations
import socket
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SaltProbePlugin(ServiceProbe):
    name = "salt"
    protocol = "tcp"
    default_ports = [4505, 4506]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # ZeroMQ ZMTP greeting
            # Signature: 0xFF + 8 padding bytes + 0x7F
            # Version: major(1) + minor(1)
            # Mechanism: 20 bytes (NULL padded)
            # As-server: 1 byte
            # Filler: 31 bytes

            greeting = b"\xff" + b"\x00" * 8 + b"\x7f"
            # Version: ZMTP 3.0
            greeting += b"\x03\x00"
            # Mechanism: "NULL" padded to 20 bytes
            mechanism = b"NULL" + b"\x00" * 16
            greeting += mechanism
            # As-server: 0 (client)
            greeting += b"\x00"
            # Filler: 31 zero bytes
            greeting += b"\x00" * 31

            conn.write(greeting)
            data = conn.read(64)
            if not data or len(data) < 10:
                return None

            # Validate ZMQ greeting response
            # First byte should be 0xFF (signature start)
            if data[0] != 0xFF:
                return None

            # Byte 9 should be 0x7F (signature end)
            if len(data) < 10 or data[9] != 0x7F:
                return None

            metadata: dict = {"protocol": "zmtp"}
            version = None

            # Extract ZMTP version from response
            if len(data) >= 12:
                zmtp_major = data[10]
                zmtp_minor = data[11]
                metadata["zmtp_version"] = f"{zmtp_major}.{zmtp_minor}"

            # Extract mechanism
            if len(data) >= 32:
                mechanism_bytes = data[12:32]
                null_pos = mechanism_bytes.find(b"\x00")
                if null_pos > 0:
                    mechanism_name = mechanism_bytes[:null_pos].decode(
                        "ascii", errors="replace"
                    )
                else:
                    mechanism_name = mechanism_bytes.decode(
                        "ascii", errors="replace"
                    ).rstrip("\x00")
                metadata["mechanism"] = mechanism_name

            # Port-based heuristic for Salt
            if conn.port == 4505:
                metadata["salt_role"] = "publish"
            elif conn.port == 4506:
                metadata["salt_role"] = "ret"

            return ServiceIdentity(
                service="salt",
                certainty=70,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
