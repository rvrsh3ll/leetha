"""Captured packet representation.

CapturedPacket is the normalized output of protocol parsers. It replaces
the old ParsedPacket with renamed fields and a cleaner interface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CapturedPacket:
    """A parsed network packet ready for processor analysis."""

    protocol: str                          # e.g. "arp", "tcp_syn", "lldp"
    hw_addr: str                           # source hardware (MAC) address
    ip_addr: str                           # source IP address
    target_ip: str | None = None           # destination IP
    target_hw: str | None = None           # destination MAC
    fields: dict = field(default_factory=dict)  # protocol-specific data
    captured_at: datetime = field(default_factory=datetime.now)
    raw: bytes | None = None               # original frame bytes
    interface: str | None = None           # capture interface name
    network: str | None = None             # CIDR network

    def get(self, key: str, default=None):
        """Shorthand for fields.get()."""
        return self.fields.get(key, default)

    # Backward-compatible property aliases so code written for the old
    # ParsedPacket (src_mac, src_ip, dst_ip, dst_mac, data, timestamp,
    # raw_bytes) continues to work without modification.

    @property
    def src_mac(self) -> str:
        return self.hw_addr

    @property
    def src_ip(self) -> str:
        return self.ip_addr

    @property
    def dst_ip(self) -> str | None:
        return self.target_ip

    @property
    def dst_mac(self) -> str | None:
        return self.target_hw

    @property
    def data(self) -> dict:
        return self.fields

    @property
    def timestamp(self) -> datetime:
        return self.captured_at

    @property
    def raw_bytes(self) -> bytes | None:
        return self.raw
