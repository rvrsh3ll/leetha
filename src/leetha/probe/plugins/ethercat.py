"""EtherCAT UDP discovery probe plugin.

EtherCAT primarily runs at Layer 2 (EtherType 0x88A4), but EtherCAT-over-Ethernet
(EoE) gateways expose UDP discovery at conn.port 34980. This probe sends a BRD
(Broadcast Read) datagram to read ESC identity registers.
"""
from __future__ import annotations

import socket
import struct

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class EtherCATProbePlugin(ServiceProbe):
    name = "ethercat"
    protocol = "udp"
    default_ports = [34980]

    # EtherCAT datagram commands
    _CMD_BRD = 0x07  # Broadcast Read

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            request = self._build_brd_request()
            conn.write(request)
            data = conn.read(4096)
            if not data or len(data) < 14:
                return None
            return self._parse_response(data)
        except (socket.timeout, OSError, struct.error):
            return None

    def _build_brd_request(self) -> bytes:
        """Build an EtherCAT BRD datagram to read ESC identity registers.

        Reads 26 bytes starting at register 0x0000:
          - ESC info (10 bytes): type, revision, build, fmmu, sm, ram, conn.port, features
          - Vendor identity (16 bytes): vendor_id, product_code, revision, serial
        """
        read_len = 26  # bytes to read from ESC registers

        # Datagram: cmd(1) + idx(1) + addr(4) + len_flags(2) + irq(2) + data(N) + wkc(2)
        cmd = self._CMD_BRD
        idx = 0x01
        addr = struct.pack("<HH", 0x0000, 0x0000)  # auto-increment addr + register offset
        len_flags = read_len & 0x07FF  # 11-bit length, no flags
        irq = 0x0000

        datagram = struct.pack("<BB", cmd, idx) + addr
        datagram += struct.pack("<HH", len_flags, irq)
        datagram += b"\x00" * read_len  # empty data for read
        datagram += struct.pack("<H", 0x0000)  # WKC starts at 0

        # Frame header: 2 bytes LE, bits [10:0] = datagram length, bits [15:12] = type (1)
        dgram_len = len(datagram)
        frame_header = struct.pack("<H", (dgram_len & 0x07FF) | (0x1 << 12))

        return frame_header + datagram

    def _parse_response(self, data: bytes) -> ServiceIdentity | None:
        """Parse EtherCAT response frame."""
        # Frame header
        frame_hdr = struct.unpack("<H", data[0:2])[0]
        frame_type = (frame_hdr >> 12) & 0x0F
        if frame_type != 1:
            return None

        dgram_len = frame_hdr & 0x07FF
        if len(data) < 2 + dgram_len:
            return None

        # Datagram header: cmd(1) + idx(1) + addr(4) + len_flags(2) + irq(2) = 10 bytes
        dgram = data[2:]
        if len(dgram) < 12:
            return None

        cmd = dgram[0]
        data_len = struct.unpack("<H", dgram[6:8])[0] & 0x07FF

        # WKC is the last 2 bytes of the datagram
        wkc_offset = 10 + data_len
        if len(dgram) < wkc_offset + 2:
            return None

        wkc = struct.unpack("<H", dgram[wkc_offset:wkc_offset + 2])[0]
        if wkc == 0:
            return None

        payload = dgram[10:10 + data_len]

        metadata: dict = {"wkc": wkc, "cmd": cmd}

        # Parse ESC identity registers (first 10 bytes)
        if len(payload) >= 10:
            esc_type, esc_rev, esc_build, fmmu, sm, ram, port_desc, features = (
                struct.unpack("<BBHBBBBH", payload[0:10])
            )
            metadata["esc_type"] = esc_type
            metadata["esc_revision"] = esc_rev
            metadata["esc_build"] = esc_build
            metadata["fmmu_count"] = fmmu
            metadata["sm_count"] = sm
            metadata["ram_size"] = ram
            metadata["port_descriptor"] = port_desc
            metadata["esc_features"] = features

        # Parse vendor identity block (next 16 bytes at offset 10)
        if len(payload) >= 26:
            vendor_id, product_code, revision, serial = struct.unpack(
                "<IIII", payload[10:26]
            )
            metadata["vendor_id"] = vendor_id
            metadata["product_code"] = product_code
            metadata["revision"] = revision
            metadata["serial"] = serial

        # Full response with vendor identity: confidence 85, partial: 75
        confidence = 85 if len(payload) >= 26 else 75

        return ServiceIdentity(
            service="ethercat",
            certainty=confidence,
            version=None,
            metadata=metadata,
        )
