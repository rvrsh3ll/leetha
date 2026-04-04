"""Passive service banner parser.

Captures server-speaks-first banners from watched TCP ports and runs them
through protocol-specific matchers to extract service identity, version,
and software information.
"""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket

_MAX_PAYLOAD = 2048


def parse_service_banner(packet) -> CapturedPacket | None:
    """Extract a service banner from a TCP payload on a watched port.

    Only inspects server -> client traffic (source port in WATCHED_PORTS).
    """
    try:
        from scapy.all import IP, TCP, Raw
    except ImportError:
        return None

    if IP not in packet or TCP not in packet:
        return None

    ip = packet[IP]
    tcp = packet[TCP]

    from leetha.capture.banner.ports import WATCHED_PORTS, service_for_port

    if tcp.sport not in WATCHED_PORTS:
        return None

    if Raw not in packet:
        return None

    payload = bytes(packet[Raw].load[:_MAX_PAYLOAD])
    if not payload:
        return None

    service_name = service_for_port(tcp.sport)
    if service_name is None:
        return None

    from leetha.capture.banner.matchers import match_banner

    result = match_banner(service_name.lower(), payload)
    if result is None:
        return None

    fields: dict = {
        "service": result.get("service", service_name.lower()),
        "version": result.get("version"),
        "software": result.get("software"),
        "raw_banner": result.get("raw_banner"),
        "server_port": tcp.sport,
        "banner_source": "server_greeting",
    }

    # Merge any extra fields from the matcher result
    for key, value in result.items():
        if key not in fields:
            fields[key] = value

    return CapturedPacket(
        protocol="service_banner",
        hw_addr=packet.src,
        ip_addr=ip.src,
        target_ip=ip.dst,
        target_hw=packet.dst,
        fields=fields,
        raw=bytes(packet) if hasattr(packet, "__bytes__") else None,
    )
