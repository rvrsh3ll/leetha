"""CDP (Cisco Discovery Protocol) parser.

Extracts device ID, platform, software version, capabilities,
IP address, and port information from CDP frames.
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


def parse_cdp(packet) -> dict | None:
    """Parse CDP frame and extract Cisco device information."""
    try:
        from scapy.contrib.cdp import (
            CDPv2_HDR, CDPMsgDeviceID, CDPMsgSoftwareVersion,
            CDPMsgPlatform, CDPMsgPortID, CDPAddrRecordIPv4,
            CDPMsgCapabilities, CDPMsgNativeVLAN, CDPMsgMgmtAddr,
        )
    except ImportError:
        return None

    if not packet.haslayer(CDPv2_HDR):
        return None

    result = {"protocol": "cdp"}

    # Device ID (hostname)
    if packet.haslayer(CDPMsgDeviceID):
        try:
            val = packet[CDPMsgDeviceID].val
            result["device_id"] = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
        except Exception:
            pass

    # Software Version
    if packet.haslayer(CDPMsgSoftwareVersion):
        try:
            val = packet[CDPMsgSoftwareVersion].val
            result["software_version"] = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
        except Exception:
            pass

    # Platform
    if packet.haslayer(CDPMsgPlatform):
        try:
            val = packet[CDPMsgPlatform].val
            result["platform"] = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
        except Exception:
            pass

    # Port ID
    if packet.haslayer(CDPMsgPortID):
        try:
            val = packet[CDPMsgPortID].iface
            result["port_id"] = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
        except Exception:
            pass

    # Capabilities
    if packet.haslayer(CDPMsgCapabilities):
        try:
            cap = int(packet[CDPMsgCapabilities].cap)
            caps = []
            if cap & 0x01: caps.append("router")
            if cap & 0x02: caps.append("transparent_bridge")
            if cap & 0x04: caps.append("source_route_bridge")
            if cap & 0x08: caps.append("switch")
            if cap & 0x10: caps.append("host")
            if cap & 0x20: caps.append("igmp")
            if cap & 0x40: caps.append("repeater")
            result["capabilities"] = caps
        except Exception:
            pass

    # Native VLAN
    if packet.haslayer(CDPMsgNativeVLAN):
        try:
            result["native_vlan"] = int(packet[CDPMsgNativeVLAN].vlan)
        except Exception:
            pass

    # Management Address
    if packet.haslayer(CDPMsgMgmtAddr):
        try:
            addr_layer = packet[CDPMsgMgmtAddr]
            if addr_layer.haslayer(CDPAddrRecordIPv4):
                result["management_ip"] = str(addr_layer[CDPAddrRecordIPv4].addr)
        except Exception:
            pass

    return result if len(result) > 1 else None
