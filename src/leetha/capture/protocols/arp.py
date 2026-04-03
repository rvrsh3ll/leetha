"""ARP protocol parser."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_arp(packet) -> CapturedPacket | None:
    """Parse ARP request/reply into CapturedPacket."""
    try:
        from scapy.layers.l2 import ARP
    except ImportError:
        return None

    if not packet.haslayer(ARP):
        return None

    arp = packet[ARP]
    if arp.op not in (1, 2):
        return None

    return CapturedPacket(
        protocol="arp",
        hw_addr=arp.hwsrc,
        ip_addr=arp.psrc,
        target_ip=arp.pdst,
        target_hw=arp.hwdst,
        fields={
            "op": arp.op,
            "src_mac": arp.hwsrc,
            "src_ip": arp.psrc,
            "dst_mac": arp.hwdst,
            "dst_ip": arp.pdst,
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
