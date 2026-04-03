"""Oracle TNS probe plugin — TNS Listener connect."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class OracleTNSProbePlugin(ServiceProbe):
    name = "oracle_tns"
    protocol = "tcp"
    default_ports = [1521, 1522, 1525]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            connect_data = (
                b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=)"
                b"(CID=(PROGRAM=)(HOST=)(USER=))))"
            )
            # TNS header: packet_length(2) + packet_checksum(2) + type(1) +
            # reserved(1) + header_checksum(2) + connect data offset(2) etc.
            # Minimal TNS CONNECT packet
            header_size = 8
            connect_data_offset = 34  # typical offset for connect data
            # Build a minimal connect packet payload
            # Fields after the 8-byte header in a CONNECT packet:
            # version(2) + compatible_version(2) + service_options(2) +
            # session_data_unit_size(2) + max_transmission_data_unit_size(2) +
            # nt_protocol_characteristics(2) + line_turnaround(2) +
            # value_of_one_in_hardware(2) + connect_data_length(2) +
            # connect_data_offset(2) + max_receivable_data(4) +
            # connect_flags_0(1) + connect_flags_1(1) + trace_cross_1(4) +
            # trace_cross_2(4) (= 32 bytes, but we use 26 to reach offset 34)
            connect_payload = struct.pack(">HH", 0x0139, 0x0139)  # version, compat
            connect_payload += struct.pack(">H", 0x0000)  # service options
            connect_payload += struct.pack(">H", 0x0800)  # SDU size
            connect_payload += struct.pack(">H", 0x7FFF)  # max TDU size
            connect_payload += struct.pack(">H", 0x0000)  # NT protocol
            connect_payload += struct.pack(">H", 0x0000)  # line turnaround
            connect_payload += struct.pack(">H", 0x0001)  # value of 1
            connect_payload += struct.pack(">H", len(connect_data))  # connect data len
            connect_payload += struct.pack(">H", connect_data_offset)  # connect data offset
            connect_payload += struct.pack(">I", 0x00000000)  # max receivable
            connect_payload += b"\x00\x00"  # connect flags
            connect_payload += b"\x00\x00\x00\x00"  # trace cross facility 1
            connect_payload += b"\x00\x00\x00\x00"  # trace cross facility 2

            packet = connect_payload + connect_data
            total_len = header_size + len(packet)
            # TNS header
            header = struct.pack(">HH", total_len, 0)  # length, checksum
            header += bytes([1])  # type = CONNECT
            header += bytes([0])  # reserved
            header += struct.pack(">H", 0)  # header checksum
            tns_packet = header + packet

            conn.write(tns_packet)
            data = conn.read(4096)
            if not data or len(data) < 8:
                return None

            # Parse TNS response header
            resp_type = data[4]
            metadata: dict = {"tns_response_type": resp_type}
            version = None

            # Type 2 = ACCEPT, Type 4 = REFUSE, Type 11 = RESEND
            if resp_type == 2:
                metadata["response"] = "accept"
                # Try to parse version from accept packet
                if len(data) >= 12:
                    tns_version = struct.unpack(">H", data[8:10])[0]
                    version = str(tns_version)
                    metadata["tns_version"] = tns_version
            elif resp_type == 4:
                metadata["response"] = "refuse"
                # Try to parse refuse reason from data
                if len(data) > 12:
                    try:
                        refuse_data = data[12:].decode("utf-8", errors="replace")
                        metadata["refuse_data"] = refuse_data[:256]
                    except Exception:
                        pass
            elif resp_type == 11:
                metadata["response"] = "resend"
            else:
                return None

            return ServiceIdentity(
                service="oracle_tns",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
