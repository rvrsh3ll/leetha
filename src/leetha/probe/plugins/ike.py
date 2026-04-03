"""IKEv2/IPsec probe plugin — sends IKE_SA_INIT request."""
from __future__ import annotations
import os
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class IKEProbePlugin(ServiceProbe):
    name = "ike"
    protocol = "udp"
    default_ports = [500, 4500]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build IKEv2 IKE_SA_INIT request
            initiator_spi = os.urandom(8)
            responder_spi = b"\x00" * 8

            # SA Payload with a minimal proposal
            # Proposal: AES-CBC-256, HMAC-SHA256, DH Group 14, PRF-HMAC-SHA256
            # Simplified SA payload
            sa_payload = self._build_sa_payload()

            next_payload = 33  # SA payload type
            version = 0x20  # IKEv2 (major 2, minor 0)
            exchange_type = 34  # IKE_SA_INIT
            flags = 0x08  # Initiator flag
            message_id = 0

            # Total length = header(28) + SA payload
            total_length = 28 + len(sa_payload)

            header = (
                initiator_spi
                + responder_spi
                + bytes([next_payload])
                + bytes([version])
                + bytes([exchange_type])
                + bytes([flags])
                + struct.pack(">I", message_id)
                + struct.pack(">I", total_length)
            )

            packet = header + sa_payload

            # For conn.port 4500, prepend 4 bytes of zero (NAT-T marker)
            if conn.port == 4500:
                packet = b"\x00" * 4 + packet

            conn.write(packet)
            data = conn.read(4096)
            if not data:
                return None

            # For NAT-T (conn.port 4500), skip the 4 zero bytes
            offset = 0
            if conn.port == 4500 and len(data) >= 4 and data[:4] == b"\x00" * 4:
                offset = 4

            if len(data) < offset + 28:
                return None

            # Parse IKE header
            resp_init_spi = data[offset:offset + 8]
            resp_resp_spi = data[offset + 8:offset + 16]
            resp_version = data[offset + 17]
            resp_exchange = data[offset + 18]

            # Check for IKEv2 response
            if resp_version != 0x20:
                return None

            # Check for IKE_SA_INIT response (exchange type 34)
            if resp_exchange != 34:
                return None

            metadata: dict = {
                "initiator_spi": resp_init_spi.hex(),
                "responder_spi": resp_resp_spi.hex(),
                "version": "2.0",
                "exchange_type": "IKE_SA_INIT",
            }

            # Check flags for responder bit
            resp_flags = data[offset + 19]
            metadata["is_responder"] = bool(resp_flags & 0x20)

            return ServiceIdentity(
                service="ike",
                certainty=85,
                version="2.0",
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None

    @staticmethod
    def _build_sa_payload() -> bytes:
        """Build a minimal IKEv2 SA payload with one proposal."""
        # Transform: ENCR_AES_CBC (12), Key Length 256
        transform_encr = struct.pack(">BBHBBH", 3, 0, 12, 1, 0, 12)
        transform_encr += struct.pack(">HH", 0x800E, 256)  # Key length attribute

        # Transform: PRF_HMAC_SHA2_256 (5)
        transform_prf = struct.pack(">BBHBBH", 3, 0, 8, 2, 0, 5)

        # Transform: AUTH_HMAC_SHA2_256_128 (12)
        transform_auth = struct.pack(">BBHBBH", 3, 0, 8, 3, 0, 12)

        # Transform: DH_GROUP_14 (14)
        transform_dh = struct.pack(">BBHBBH", 0, 0, 8, 4, 0, 14)

        transforms = transform_encr + transform_prf + transform_auth + transform_dh

        # Proposal: protocol IKE (1), 4 transforms
        proposal_header = struct.pack(">BBHBBBB",
                                      0,    # last proposal (0)
                                      0,    # reserved
                                      8 + len(transforms),  # proposal length
                                      1,    # proposal number
                                      1,    # protocol ID: IKE
                                      0,    # SPI size
                                      4,    # num transforms
                                      )
        proposal = proposal_header + transforms

        # SA payload header: next payload(1) + critical(1) + length(2)
        sa_header = struct.pack(">BBH",
                                0,    # next payload: none
                                0,    # critical bit
                                4 + len(proposal),  # payload length
                                )
        return sa_header + proposal
