"""HTTP User-Agent parser."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def parse_http_useragent(packet) -> CapturedPacket | None:
    """Extract User-Agent from unencrypted HTTP requests."""
    from scapy.all import IP, TCP, Raw

    if TCP not in packet or Raw not in packet or IP not in packet:
        return None

    try:
        payload = bytes(packet[Raw].load)
        text = payload[:2048].decode("utf-8", errors="ignore")
    except Exception:
        return None

    if not text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ", "OPTIONS ")):
        return None

    first_line = text.split("\r\n", 1)[0]
    parts = first_line.split(" ", 2)
    if len(parts) < 2:
        return None
    method, path = parts[0], parts[1]

    user_agent = None
    host = None
    for line in text.split("\r\n")[1:]:
        if not line:
            break
        lower = line.lower()
        if lower.startswith("user-agent:"):
            user_agent = line.split(":", 1)[1].strip()
        elif lower.startswith("host:"):
            host = line.split(":", 1)[1].strip()

    if not user_agent:
        return None

    src_mac = packet.src if hasattr(packet, "src") else ""

    return CapturedPacket(
        protocol="http_useragent",
        hw_addr=src_mac,
        ip_addr=packet[IP].src,
        target_ip=packet[IP].dst,
        fields={
            "user_agent": user_agent,
            "host": host,
            "method": method,
            "path": path,
        },
    )
