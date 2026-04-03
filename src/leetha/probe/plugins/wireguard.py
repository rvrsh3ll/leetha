"""WireGuard probe plugin — heuristic detection via handshake initiation."""
from __future__ import annotations
import os
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class WireGuardProbePlugin(ServiceProbe):
    name = "wireguard"
    protocol = "udp"
    default_ports = [51820]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build WireGuard Handshake Initiation message
            # Type: 1 (handshake initiation), 4 bytes little-endian
            msg_type = struct.pack("<I", 1)
            # Sender index: 4 bytes
            sender_index = struct.pack("<I", 0x12345678)
            # Unencrypted ephemeral: 32 bytes (random)
            ephemeral = os.urandom(32)
            # Encrypted static: 48 bytes (random, will be invalid)
            encrypted_static = os.urandom(48)
            # Encrypted timestamp: 28 bytes (random, will be invalid)
            encrypted_timestamp = os.urandom(28)
            # MAC1: 16 bytes
            mac1 = os.urandom(16)
            # MAC2: 16 bytes
            mac2 = b"\x00" * 16

            packet = (
                msg_type + sender_index + ephemeral
                + encrypted_static + encrypted_timestamp
                + mac1 + mac2
            )

            # WireGuard silently discards invalid handshakes by design.
            # We use a heuristic: if the conn.port is open (no ICMP unreachable),
            # it could be WireGuard. We send the packet and check for
            # any response or lack of error.
            original_timeout = conn.raw_socket.gettimeout()
            conn.set_timeout(2)

            conn.write(packet)

            try:
                data = conn.read(4096)
                if data and len(data) >= 4:
                    # Check for handshake response (type 2)
                    resp_type = struct.unpack("<I", data[:4])[0]
                    if resp_type == 2:
                        metadata = {"response_type": "handshake_response"}
                        if len(data) >= 8:
                            metadata["sender_index"] = struct.unpack(
                                "<I", data[4:8]
                            )[0]
                        return ServiceIdentity(
                            service="wireguard",
                            certainty=75,
                            metadata=metadata,
                        )
                    # Cookie reply (type 3)
                    if resp_type == 3:
                        return ServiceIdentity(
                            service="wireguard",
                            certainty=70,
                            metadata={"response_type": "cookie_reply"},
                        )
                # Got some data but not a recognized WireGuard response
                return None
            except socket.timeout:
                # No response - WireGuard silently discards invalid handshakes.
                # The absence of ICMP unreachable suggests a listener exists.
                # This is a low-confidence heuristic detection.
                return ServiceIdentity(
                    service="wireguard",
                    certainty=50,
                    metadata={"detection": "heuristic", "note": "silent_discard"},
                )
        except (socket.timeout, OSError):
            return None
