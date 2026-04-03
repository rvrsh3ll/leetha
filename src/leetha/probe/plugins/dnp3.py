"""DNP3 probe plugin — Data Link Layer request for Device Attributes."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DNP3ProbePlugin(ServiceProbe):
    name = "dnp3"
    protocol = "tcp"
    default_ports = [20000]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # DNP3 Data Link Layer frame
            # Start bytes: 0x0564
            # Length: number of bytes in the rest of the frame (excluding start + length)
            # Control: 0xC0 (DIR=1, PRM=1, FCB=0, FCV=0, FC=0 Reset Link States)
            # Destination address: 1 (outstation)
            # Source address: 3 (master)
            dst_addr = 1
            src_addr = 3

            # Build a minimal DNP3 request:
            # Read Class 0 data (integrity poll)
            # Transport header: FIN=1, FIR=1, sequence=0 -> 0xC0
            # Application header: Control=0xC0 (FIR=1,FIN=1,CON=0,UNS=0,SEQ=0)
            #                     Function code: 0x01 (READ)
            # Object header: Group 60 (Class Data), Variation 1 (Class 0)
            #                Qualifier 0x06 (All objects)
            transport_header = b"\xC0"
            app_control = b"\xC0"  # FIR=1, FIN=1
            func_code = b"\x01"    # READ
            obj_header = bytes([
                0x3C, 0x01,  # Group 60, Variation 1 (Class 0)
                0x06,        # Qualifier: All objects
            ])

            user_data = transport_header + app_control + func_code + obj_header

            # Data link layer frame
            dl_length = 5 + len(user_data)  # 5 = control(1) + dst(2) + src(2)
            control = 0xC4  # DIR=1, PRM=1, FCB=0, FCV=0, FC=4 (Unconfirmed User Data)

            frame = struct.pack(
                "<BBBBHH",
                0x05,        # Start byte 1
                0x64,        # Start byte 2
                dl_length,   # Length
                control,     # Control
                dst_addr,    # Destination
                src_addr,    # Source
            )

            # Calculate CRC for the header (first 8 bytes, excluding start bytes actually
            # DNP3 uses CRC-16 on blocks, but for probing we send raw and see if we get a response)
            crc = self._crc16(frame[2:8])
            frame += struct.pack("<H", crc)

            # Add user data with CRC
            frame += user_data
            data_crc = self._crc16(user_data)
            frame += struct.pack("<H", data_crc)

            conn.write(frame)
            data = conn.read(4096)
            if not data or len(data) < 10:
                return None

            # Check for DNP3 start bytes 0x05 0x64
            if data[0] != 0x05 or data[1] != 0x64:
                return None

            metadata = {}
            # Parse response Data Link Layer header
            resp_length = data[2]
            resp_control = data[3]
            resp_dst = struct.unpack("<H", data[4:6])[0]
            resp_src = struct.unpack("<H", data[6:8])[0]

            metadata["dl_length"] = resp_length
            metadata["dl_control"] = resp_control
            metadata["destination_address"] = resp_dst
            metadata["source_address"] = resp_src

            # Check direction bit and primary bit
            metadata["dir"] = bool(resp_control & 0x80)
            metadata["prm"] = bool(resp_control & 0x40)

            return ServiceIdentity(
                service="dnp3",
                certainty=85,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None

    @staticmethod
    def _crc16(data: bytes) -> int:
        """Compute DNP3 CRC-16 (CRC-16/DNP)."""
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return crc ^ 0xFFFF
