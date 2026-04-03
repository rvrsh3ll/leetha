"""TACACS+ probe plugin — Terminal Access Controller Access-Control System Plus."""
from __future__ import annotations
import os
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class TACACSProbePlugin(ServiceProbe):
    name = "tacacs"
    protocol = "tcp"
    default_ports = [49]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Build TACACS+ Authentication START packet
            # Header: 12 bytes
            major_version = 0x0C  # TAC_PLUS_MAJOR_VER = 0xC
            minor_version = 0x00
            version = (major_version << 4) | minor_version  # 0xC0

            authen_type = 1   # TAC_PLUS_AUTHEN (authentication)
            seq_no = 1        # Sequence number
            flags = 0x01      # TAC_PLUS_UNENCRYPTED_FLAG
            session_id = struct.unpack(">I", os.urandom(4))[0]

            # Authentication START body
            action = 1       # TAC_PLUS_AUTHEN_LOGIN
            priv_lvl = 1     # TAC_PLUS_PRIV_LVL_USER
            authen_type_body = 1  # TAC_PLUS_AUTHEN_TYPE_ASCII
            authen_service = 1    # TAC_PLUS_AUTHEN_SVC_LOGIN
            user = b""
            port_field = b""
            rem_addr = b""
            data_field = b""

            body = struct.pack(
                "BBBBBBBB",
                action, priv_lvl, authen_type_body, authen_service,
                len(user), len(port_field), len(rem_addr), len(data_field),
            )
            body += user + port_field + rem_addr + data_field

            # TACACS+ header: version(1) + type(1) + seq_no(1) + flags(1)
            # + session_id(4) + length(4) = 12 bytes
            header = struct.pack(
                ">BBBBI",
                version,
                authen_type,
                seq_no,
                flags,
                session_id,
            ) + struct.pack(">I", len(body))

            conn.write(header + body)
            data = conn.read(4096)

            if not data or len(data) < 12:
                return None

            # Parse TACACS+ response header
            resp_version = data[0]
            resp_type = data[1]
            resp_seq = data[2]
            resp_flags = data[3]
            resp_session_id = struct.unpack(">I", data[4:8])[0]
            resp_body_len = struct.unpack(">I", data[8:12])[0]

            # Validate TACACS+ response
            # Major version should be 0xC (top nibble)
            if (resp_version >> 4) != 0x0C:
                return None

            metadata: dict = {
                "version": hex(resp_version),
                "type": resp_type,
                "seq_no": resp_seq,
                "flags": resp_flags,
                "body_length": resp_body_len,
            }

            # Parse authentication REPLY body if present
            if resp_type == 1 and resp_body_len >= 6 and len(data) >= 12 + 6:
                body_data = data[12:]
                status = body_data[0]
                status_names = {
                    1: "PASS", 2: "FAIL", 3: "GETDATA",
                    4: "GETUSER", 5: "GETPASS", 6: "RESTART",
                    7: "ERROR", 21: "FOLLOW",
                }
                metadata["authen_status"] = status_names.get(status, f"unknown({status})")

            return ServiceIdentity(
                service="tacacs",
                certainty=80,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
