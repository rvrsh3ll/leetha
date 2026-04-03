"""ZeroTier probe plugin — sends ZeroTier HELLO packet."""
from __future__ import annotations
import os
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ZeroTierProbePlugin(ServiceProbe):
    name = "zerotier"
    protocol = "udp"
    default_ports = [9993]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build ZeroTier HELLO packet
            # ZeroTier packet format:
            # Fragment indicator (1 byte): if top bit not set, it's a full packet
            # Destination (5 bytes): ZT address
            # Source (5 bytes): ZT address
            # Flags/Cipher/Hops (1 byte)
            # Verb (1 byte): 0x01 = HELLO

            # Use a random source address (5 bytes)
            source_addr = os.urandom(5)
            # Destination: broadcast or ZeroTier root server address
            dest_addr = b"\xff\xff\xff\xff\xff"

            # Flags: unencrypted (cipher=0), hops=0
            flags_cipher_hops = 0x00

            # Verb: HELLO (1)
            verb = 0x01

            # HELLO payload:
            # Protocol version (1 byte)
            # Major version (1 byte)
            # Minor version (1 byte)
            # Revision (2 bytes)
            # Timestamp (8 bytes)
            # Identity (variable)
            protocol_version = 12  # Current ZT protocol version
            major_version = 1
            minor_version = 12
            revision = 0

            hello_payload = struct.pack(">BBBH",
                                        protocol_version,
                                        major_version,
                                        minor_version,
                                        revision,
                                        )
            hello_payload += struct.pack(">Q", 0)  # Timestamp

            # Minimal identity (just enough to be parsed)
            # ZT address (5 bytes) + identity type(1) + key material
            hello_payload += source_addr  # address
            hello_payload += b"\x00"  # identity type 0 (curve25519)
            hello_payload += os.urandom(64)  # public key material (c25519)

            # Build full packet
            packet = (
                dest_addr
                + source_addr
                + bytes([flags_cipher_hops])
                + bytes([verb])
                + hello_payload
            )

            conn.write(packet)
            data = conn.read(4096)
            if not data or len(data) < 12:
                return None

            # Parse ZeroTier response
            # Check if this looks like a ZeroTier packet
            # Minimum: dest(5) + source(5) + flags(1) + verb(1) = 12 bytes
            resp_verb = data[11] & 0x1F  # verb is lower 5 bits

            metadata: dict = {
                "response_verb": resp_verb,
            }

            # HELLO response is OK (verb 2)
            if resp_verb == 0x02:
                metadata["response_type"] = "OK"
                # Try to extract version info
                if len(data) > 20:
                    # OK payload contains: in-re verb(1) + in-re packet ID
                    # then HELLO-specific OK: timestamp + protocol ver + major + minor + revision
                    pass
                return ServiceIdentity(
                    service="zerotier",
                    certainty=70,
                    metadata=metadata,
                )

            # ERROR response (verb 3)
            if resp_verb == 0x03:
                metadata["response_type"] = "ERROR"
                return ServiceIdentity(
                    service="zerotier",
                    certainty=70,
                    metadata=metadata,
                )

            # Any other valid-looking ZeroTier response
            if resp_verb in (0x01, 0x04, 0x05, 0x06, 0x07, 0x08):
                metadata["response_type"] = f"verb_{resp_verb}"
                return ServiceIdentity(
                    service="zerotier",
                    certainty=60,
                    metadata=metadata,
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None
