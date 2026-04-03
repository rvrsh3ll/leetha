"""AFP probe plugin — DSI GetStatus to detect Apple Filing Protocol services."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class AFPProbePlugin(ServiceProbe):
    name = "afp"
    protocol = "tcp"
    default_ports = [548]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build DSI GetStatus request
            # DSI header: flags(1) + command(1) + requestID(2) +
            #             errorCode/dataOffset(4) + totalDataLength(4) + reserved(4)
            flags = 0x00      # Request
            command = 0x03    # DSIGetStatus
            request_id = 1
            data_offset = 0
            total_length = 0
            reserved = 0

            dsi_header = struct.pack(
                ">BBHIII",
                flags, command, request_id,
                data_offset, total_length, reserved,
            )

            conn.write(dsi_header)
            data = conn.read(4096)
            if not data or len(data) < 16:
                return None

            # Parse DSI reply header
            reply_flags = data[0]
            reply_command = data[1]

            # Check for DSI reply (flags=0x01) with GetStatus command (0x03)
            if reply_flags != 0x01:
                return None
            if reply_command != 0x03:
                return None

            reply_id = struct.unpack_from(">H", data, 2)[0]
            error_code = struct.unpack_from(">I", data, 4)[0]
            data_length = struct.unpack_from(">I", data, 8)[0]

            metadata: dict = {
                "request_id": reply_id,
                "error_code": error_code,
            }

            # Parse server info block from DSI payload (starts at offset 16)
            payload = data[16:]
            if len(payload) >= 16:
                # Server info block offsets
                # machine_type_offset(2) + afp_versions_offset(2) +
                # uam_list_offset(2) + volume_icon_offset(2) + flags(2) +
                # server_name (pascal string)
                machine_type_off = struct.unpack_from(">H", payload, 0)[0]
                afp_versions_off = struct.unpack_from(">H", payload, 2)[0]
                server_flags = struct.unpack_from(">H", payload, 8)[0]
                metadata["server_flags"] = server_flags

                # Server name is a pascal string at offset 10
                if len(payload) > 10:
                    name_len = payload[10]
                    if len(payload) > 11 + name_len:
                        server_name = payload[11:11 + name_len].decode(
                            "utf-8", errors="replace"
                        )
                        metadata["server_name"] = server_name

                # Try to read machine type string
                if machine_type_off > 0 and machine_type_off < len(payload) - 1:
                    mt_len = payload[machine_type_off]
                    if machine_type_off + 1 + mt_len <= len(payload):
                        machine_type = payload[
                            machine_type_off + 1:machine_type_off + 1 + mt_len
                        ].decode("utf-8", errors="replace")
                        metadata["machine_type"] = machine_type

            version = metadata.get("machine_type")
            return ServiceIdentity(
                service="afp",
                certainty=85,
                version=version,
                banner=None,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
