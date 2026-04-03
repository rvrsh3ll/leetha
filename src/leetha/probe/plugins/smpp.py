"""SMPP probe plugin — bind_receiver PDU for SMS gateway detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class SMPPProbePlugin(ServiceProbe):
    name = "smpp"
    protocol = "tcp"
    default_ports = [2775, 2776]

    # SMPP command IDs
    _CMD_BIND_RECEIVER = 0x00000001
    _CMD_BIND_RECEIVER_RESP = 0x80000001

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build SMPP bind_receiver PDU
            # Body: null-terminated strings and single-byte fields
            system_id = b"leetha\x00"
            password = b"\x00"
            system_type = b"\x00"
            interface_version = bytes([0x34])  # SMPP v3.4
            addr_ton = bytes([0x00])
            addr_npi = bytes([0x00])
            addr_range = b"\x00"

            body = system_id + password + system_type + interface_version + addr_ton + addr_npi + addr_range

            # Header: command_length(4) + command_id(4) + command_status(4) + sequence_number(4)
            command_length = 16 + len(body)
            header = struct.pack(">I", command_length)
            header += struct.pack(">I", self._CMD_BIND_RECEIVER)
            header += struct.pack(">I", 0)  # command_status: 0
            header += struct.pack(">I", 1)  # sequence_number: 1

            conn.write(header + body)
            data = conn.read(4096)
            if not data or len(data) < 16:
                return None

            # Parse SMPP response header
            resp_length = struct.unpack(">I", data[0:4])[0]
            resp_cmd_id = struct.unpack(">I", data[4:8])[0]
            resp_status = struct.unpack(">I", data[8:12])[0]
            resp_seq = struct.unpack(">I", data[12:16])[0]

            # Check for bind_receiver_resp
            if resp_cmd_id != self._CMD_BIND_RECEIVER_RESP:
                return None

            metadata: dict = {
                "command_status": resp_status,
                "sequence_number": resp_seq,
            }

            # Parse system_id from response body if present
            if len(data) > 16:
                body_data = data[16:]
                null_idx = body_data.find(b"\x00")
                if null_idx > 0:
                    metadata["system_id"] = body_data[:null_idx].decode("utf-8", errors="replace")

            return ServiceIdentity(
                service="smpp",
                certainty=80,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
