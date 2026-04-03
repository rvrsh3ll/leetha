"""Modbus/TCP probe plugin — Read Device Identification (FC 0x2B/0x0E)."""

from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class ModbusProbePlugin(ServiceProbe):
    name = "modbus"
    protocol = "tcp"
    default_ports = [502]

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = struct.pack(
                ">HHHBBBB",
                0x0001, 0x0000, 0x0005, 0x01, 0x2B, 0x0E, 0x01,
            ) + b"\x00"

            conn.write(request)
            data = conn.read(1024)

            if not data or len(data) < 9:
                return None

            proto_id = struct.unpack(">H", data[2:4])[0]
            if proto_id != 0:
                return None

            func_code = data[7]
            if func_code == 0x2B:
                return self._parse_device_id(data)
            elif func_code == 0xAB:
                return ServiceIdentity(
                    service="modbus",
                    certainty=85,
                    metadata={"error": True, "exception_code": data[8] if len(data) > 8 else None},
                )

            return None
        except (socket.timeout, OSError, struct.error):
            return None

    def _parse_device_id(self, data: bytes) -> ServiceIdentity:
        metadata: dict = {}
        try:
            offset = 9
            if len(data) > offset + 4:
                num_objects = data[offset + 3]
                offset += 4

                obj_names = {0: "vendor", 1: "product_code", 2: "revision"}
                for _ in range(num_objects):
                    if offset + 2 > len(data):
                        break
                    obj_id = data[offset]
                    obj_len = data[offset + 1]
                    offset += 2
                    if offset + obj_len > len(data):
                        break
                    obj_val = data[offset:offset + obj_len].decode("utf-8", errors="replace")
                    metadata[obj_names.get(obj_id, f"obj_{obj_id}")] = obj_val
                    offset += obj_len
        except (IndexError, struct.error):
            pass

        version = metadata.get("revision") or metadata.get("product_code")
        return ServiceIdentity(service="modbus", version=version, metadata=metadata, certainty=90)
