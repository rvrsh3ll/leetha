"""Device timeline builder — synthesizes temporal data into a chronological event feed."""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)


def _parse_observation_title(source_type: str, raw_data_str: str) -> str:
    try:
        data = json.loads(raw_data_str) if isinstance(raw_data_str, str) else raw_data_str
    except (json.JSONDecodeError, TypeError):
        data = {}

    if source_type == "dhcpv4":
        hn = data.get("hostname")
        return f"DHCP hostname: {hn}" if hn else "DHCP exchange"
    elif source_type == "arp":
        ip = data.get("src_ip") or data.get("ip")
        return f"ARP: {ip}" if ip else "ARP exchange"
    elif source_type == "mdns":
        svc = data.get("service") or data.get("name")
        return f"mDNS service: {svc}" if svc else "mDNS announcement"
    elif source_type == "dns":
        q = data.get("query") or data.get("name")
        return f"DNS query: {q}" if q else "DNS activity"
    elif source_type == "tls_client_hello":
        sni = data.get("sni") or data.get("server_name")
        return f"TLS connection: {sni}" if sni else "TLS handshake"
    elif source_type == "http_useragent":
        ua = data.get("user_agent") or data.get("ua")
        if ua and len(ua) > 60:
            ua = ua[:60] + "..."
        return f"HTTP User-Agent: {ua}" if ua else "HTTP request"
    elif source_type == "ssdp":
        srv = data.get("server") or data.get("st")
        return f"SSDP: {srv}" if srv else "UPnP discovery"
    elif source_type in ("lldp", "cdp"):
        name = data.get("system_name") or data.get("device_id")
        return f"{source_type.upper()} neighbor: {name}" if name else f"{source_type.upper()} announcement"
    elif source_type == "tcp_syn":
        return "TCP SYN fingerprint"
    elif source_type == "icmpv6":
        t = data.get("type")
        return f"ICMPv6 type {t}" if t else "ICMPv6 packet"
    elif source_type == "ip_observed":
        return "IP traffic observed"
    else:
        return f"{source_type} observation"


def build_timeline(
    *,
    mac: str,
    device: dict | None,
    observations: list[dict],
    fingerprint_history: list[dict],
    arp_history: list[dict],
    findings: list[dict],
    limit: int = 200,
) -> list[dict]:
    events: list[dict] = []

    if device and device.get("first_seen"):
        events.append({
            "timestamp": device["first_seen"],
            "type": "first_seen",
            "title": "Device first discovered",
            "detail": f"Hostname: {device.get('hostname')}" if device.get("hostname") else "Unknown device",
            "source": None,
        })

    for obs in observations:
        ts = obs.get("timestamp")
        if not ts:
            continue
        source = obs.get("source_type", "unknown")
        title = _parse_observation_title(source, obs.get("raw_data", "{}"))
        events.append({
            "timestamp": ts,
            "type": "observation",
            "title": title,
            "detail": f"Source: {source} — confidence: {obs.get('confidence', '?')}%",
            "source": source,
        })

    for snap in fingerprint_history:
        ts = snap.get("timestamp")
        if not ts:
            continue
        parts = []
        if snap.get("device_type"):
            parts.append(snap["device_type"])
        if snap.get("manufacturer"):
            parts.append(snap["manufacturer"])
        if snap.get("os_family"):
            parts.append(snap["os_family"])
        title = f"Classified as {' — '.join(parts)}" if parts else "Classification: unknown"
        detail_parts = []
        if snap.get("hostname"):
            detail_parts.append(f"hostname: {snap['hostname']}")
        if snap.get("oui_vendor"):
            detail_parts.append(f"OUI: {snap['oui_vendor']}")
        events.append({
            "timestamp": ts,
            "type": "classification",
            "title": title,
            "detail": ", ".join(detail_parts) if detail_parts else None,
            "source": "fingerprint",
        })

    for entry in arp_history:
        ts = entry.get("first_seen")
        if not ts:
            continue
        events.append({
            "timestamp": ts,
            "type": "ip_change",
            "title": f"IP address: {entry.get('ip', '?')}",
            "detail": f"Packets: {entry.get('packet_count', 0)} — last seen: {entry.get('last_seen', '?')}",
            "source": "arp",
        })

    for f in findings:
        ts = f.get("timestamp")
        if not ts:
            continue
        events.append({
            "timestamp": ts,
            "type": "finding",
            "title": f.get("alert_type", "unknown"),
            "detail": f"[{f.get('severity', 'info').upper()}] {f.get('message', '')}",
            "source": "rule",
        })

    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events[:limit]
