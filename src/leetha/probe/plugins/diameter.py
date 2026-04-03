"""Diameter probe plugin — Capabilities-Exchange-Request for telecom diameter detection."""
from __future__ import annotations
import socket
import struct
from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class DiameterProbePlugin(ServiceProbe):
    name = "diameter"
    protocol = "tcp"
    default_ports = [3868]

    # Diameter AVP codes
    _AVP_ORIGIN_HOST = 264
    _AVP_ORIGIN_REALM = 296
    _AVP_PRODUCT_NAME = 269

    def _build_avp(self, code: int, flags: int, data: bytes) -> bytes:
        """Build a Diameter AVP."""
        # AVP header: code(4) + flags(1) + length(3)
        avp_len = 8 + len(data)
        header = struct.pack(">I", code)
        header += struct.pack("B", flags)
        # Length is 3 bytes (24 bits)
        header += struct.pack(">I", avp_len)[1:]  # Take last 3 bytes
        avp = header + data
        # Pad to 4-byte boundary
        padding = (4 - (len(avp) % 4)) % 4
        avp += b"\x00" * padding
        return avp

    def _build_cer(self) -> bytes:
        """Build a Capabilities-Exchange-Request message."""
        # Build AVPs
        origin_host = self._build_avp(
            self._AVP_ORIGIN_HOST, 0x40,  # Mandatory
            b"leetha.localhost"
        )
        origin_realm = self._build_avp(
            self._AVP_ORIGIN_REALM, 0x40,
            b"localhost"
        )
        # Host-IP-Address AVP (257), mandatory
        host_ip = self._build_avp(
            257, 0x40,
            struct.pack(">H", 1) + b"\x7f\x00\x00\x01"  # IPv4 127.0.0.1
        )
        # Vendor-Id AVP (266), mandatory
        vendor_id = self._build_avp(266, 0x40, struct.pack(">I", 0))
        # Product-Name AVP (269)
        product_name = self._build_avp(self._AVP_PRODUCT_NAME, 0x00, b"leetha")

        avps = origin_host + origin_realm + host_ip + vendor_id + product_name

        # Diameter header: version(1) + message_length(3) + flags(1) + command(3) + app_id(4) + hop_by_hop(4) + end_to_end(4)
        msg_length = 20 + len(avps)
        header = struct.pack("B", 1)  # Version
        header += struct.pack(">I", msg_length)[1:]  # Length (3 bytes)
        header += struct.pack("B", 0x80)  # Flags: R bit set (Request)
        header += struct.pack(">I", 257)[1:]  # Command code: CER (3 bytes)
        header += struct.pack(">I", 0)  # Application ID
        header += struct.pack(">I", 0x706F6E67)  # Hop-by-Hop ID
        header += struct.pack(">I", 0x706F6E67)  # End-to-End ID

        return header + avps

    def _parse_avp_string(self, data: bytes, offset: int, avp_len: int) -> str:
        """Extract string value from AVP data."""
        value_start = offset + 8
        value_len = avp_len - 8
        if value_start + value_len > len(data):
            return ""
        return data[value_start:value_start + value_len].decode("utf-8", errors="replace")

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            cer = self._build_cer()
            conn.write(cer)
            data = conn.read(4096)
            if not data or len(data) < 20:
                return None

            # Parse Diameter header
            version = data[0]
            if version != 1:
                return None

            msg_length = struct.unpack(">I", b"\x00" + data[1:4])[0]
            flags = data[4]
            command_code = struct.unpack(">I", b"\x00" + data[5:8])[0]

            # Check for CEA (command 257, R bit clear)
            if command_code != 257:
                return None
            if flags & 0x80:  # R bit should be clear for answer
                return None

            metadata: dict = {
                "command_code": command_code,
                "message_length": msg_length,
            }
            version_str = None

            # Parse AVPs
            offset = 20
            while offset + 8 <= len(data):
                avp_code = struct.unpack(">I", data[offset:offset + 4])[0]
                avp_flags = data[offset + 4]
                avp_len = struct.unpack(">I", b"\x00" + data[offset + 5:offset + 8])[0]

                if avp_len < 8:
                    break

                if avp_code == self._AVP_ORIGIN_HOST:
                    metadata["origin_host"] = self._parse_avp_string(data, offset, avp_len)
                elif avp_code == self._AVP_ORIGIN_REALM:
                    metadata["origin_realm"] = self._parse_avp_string(data, offset, avp_len)
                elif avp_code == self._AVP_PRODUCT_NAME:
                    product = self._parse_avp_string(data, offset, avp_len)
                    metadata["product_name"] = product
                    version_str = product

                # Advance to next AVP (padded to 4-byte boundary)
                padded_len = avp_len + ((4 - (avp_len % 4)) % 4)
                offset += padded_len

            return ServiceIdentity(
                service="diameter",
                certainty=85,
                version=version_str,
                metadata=metadata,
            )
        except (socket.timeout, OSError, struct.error):
            return None
