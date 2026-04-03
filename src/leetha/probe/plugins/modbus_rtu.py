"""Modbus RTU over TCP probe plugin — Report Server ID (FC 0x11).

Targets serial-to-Ethernet converters bridging legacy Modbus RTU devices.
RTU framing has no MBAP header — raw ADU with CRC-16 checksum.
"""

from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

def _crc16_modbus(data: bytes) -> int:
    """Compute Modbus CRC-16 (init=0xFFFF, poly=0xA001 reflected)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc

class ModbusRTUProbePlugin(ServiceProbe):
    name = "modbus_rtu"
    protocol = "tcp"
    default_ports = [502]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # FC 0x11 Report Server ID — RTU frame: slave_addr + fc + CRC16
            slave_addr = 0x01
            fc = 0x11
            payload = struct.pack("BB", slave_addr, fc)
            crc = _crc16_modbus(payload)
            request = payload + struct.pack("<H", crc)

            conn.write(request)
            data = conn.read(1024)

            if not data or len(data) < 5:
                return None

            # Validate CRC: last 2 bytes are CRC-16 LE
            frame_body = data[:-2]
            recv_crc = struct.unpack("<H", data[-2:])[0]
            if _crc16_modbus(frame_body) != recv_crc:
                return None

            resp_slave = data[0]
            resp_fc = data[1]

            # Exception response: FC has bit 7 set
            if resp_fc & 0x80:
                exception_code = data[2] if len(data) > 2 else None
                return ServiceIdentity(
                    service="modbus_rtu",
                    certainty=85,
                    metadata={
                        "error": True,
                        "slave_addr": resp_slave,
                        "exception_code": exception_code,
                    },
                )

            # Normal FC 0x11 response
            if resp_fc == 0x11:
                return self._parse_server_id(data)

            # Some other valid FC response — partial detection
            return ServiceIdentity(
                service="modbus_rtu",
                certainty=80,
                metadata={"slave_addr": resp_slave, "func_code": resp_fc},
            )

        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_server_id(self, data: bytes) -> ServiceIdentity:
        """Parse FC 0x11 Report Server ID response."""
        metadata: dict = {"slave_addr": data[0]}
        try:
            byte_count = data[2]
            # server_id is byte_count-1 bytes (last byte is run_status)
            id_end = 3 + byte_count - 1
            server_id_bytes = data[3:id_end]
            run_status_byte = data[id_end]

            metadata["server_id"] = server_id_bytes.decode("ascii", errors="replace")
            metadata["run_status"] = "running" if run_status_byte == 0xFF else "idle"
        except (IndexError, struct.error):
            pass

        version = metadata.get("server_id")
        return ServiceIdentity(
            service="modbus_rtu",
            version=version,
            metadata=metadata,
            certainty=90,
        )
