"""Mitsubishi MELSEC-Q (MC Protocol) probe plugin — Binary read command."""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class MELSECProbePlugin(ServiceProbe):
    name = "melsec"
    protocol = "tcp"
    default_ports = [5000, 5001]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # MC Protocol binary format (QnA-compatible 3E frame)
            # Subheader: 0x5000 (binary request)
            # Network No.: 0x00
            # PC No.: 0xFF
            # Request destination module I/O: 0x03FF
            # Request destination module station: 0x00
            # Data length: varies (monitoring timer + command + subcommand + data)
            # Monitoring timer: 0x000A (10 * 250ms = 2.5s)
            # Command: 0x0401 (Read device in batch)
            # Subcommand: 0x0000 (word units)
            # Head device: D0 (data register 0)
            # Device code: 0xA8 (D register)
            # Number of device points: 1

            # Request body: timer + command + subcommand + head device + device code + points
            timer = struct.pack("<H", 0x000A)       # Monitoring timer
            command = struct.pack("<H", 0x0401)      # Batch read
            subcommand = struct.pack("<H", 0x0000)   # Word units
            head_device = struct.pack("<I", 0x000000)[:3]  # Head device number (3 bytes)
            device_code = struct.pack("<B", 0xA8)    # D register
            num_points = struct.pack("<H", 0x0001)   # 1 point

            body = timer + command + subcommand + head_device + device_code + num_points

            # Build 3E frame header
            subheader = struct.pack(">H", 0x5000)    # Subheader (big-endian for MC protocol)
            network_no = struct.pack("<B", 0x00)
            pc_no = struct.pack("<B", 0xFF)
            io_number = struct.pack("<H", 0x03FF)
            station_no = struct.pack("<B", 0x00)
            data_length = struct.pack("<H", len(body))

            request = (
                subheader + network_no + pc_no + io_number + station_no
                + data_length + body
            )

            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 9:
                return None

            # Parse response subheader
            resp_subheader = struct.unpack(">H", data[0:2])[0]

            # Response subheader should be 0xD000 (binary response)
            if resp_subheader != 0xD000:
                return None

            metadata = {
                "subheader": f"0x{resp_subheader:04X}",
            }

            # Parse response fields
            if len(data) >= 7:
                resp_network = data[2]
                resp_pc = data[3]
                resp_io = struct.unpack("<H", data[4:6])[0]
                resp_station = data[6]
                metadata["network_no"] = resp_network
                metadata["pc_no"] = resp_pc
                metadata["io_number"] = resp_io
                metadata["station_no"] = resp_station

            # Parse data length and end code
            if len(data) >= 11:
                resp_data_length = struct.unpack("<H", data[7:9])[0]
                metadata["data_length"] = resp_data_length
                end_code = struct.unpack("<H", data[9:11])[0]
                metadata["end_code"] = end_code

            return ServiceIdentity(
                service="melsec",
                certainty=85,
                metadata=metadata,
            )

        except (socket.timeout, OSError, struct.error):
            return None
