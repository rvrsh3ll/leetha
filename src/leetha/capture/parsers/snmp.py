"""SNMP (Simple Network Management Protocol) parser.

Extracts community strings (v1/v2c -- plaintext), version,
and PDU type from SNMP packets.
"""

from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


def parse_snmp(packet) -> dict | None:
    """Parse SNMP packet and extract community string and version."""
    try:
        from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPset, SNMPtrapv1
    except ImportError:
        return None

    if not packet.haslayer(SNMP):
        return None

    snmp = packet[SNMP]
    result = {"protocol": "snmp"}

    try:
        # Version
        version = int(snmp.version)
        result["version"] = {0: "v1", 1: "v2c", 3: "v3"}.get(version, f"v{version}")

        # Community string (only in v1/v2c -- plaintext!)
        if hasattr(snmp, "community") and snmp.community:
            community = snmp.community
            if isinstance(community, bytes):
                community = community.decode("utf-8", errors="replace")
            result["community"] = str(community)

        # PDU type
        if snmp.haslayer(SNMPget):
            result["pdu_type"] = "get-request"
        elif snmp.haslayer(SNMPresponse):
            result["pdu_type"] = "get-response"
        elif snmp.haslayer(SNMPset):
            result["pdu_type"] = "set-request"
        elif snmp.haslayer(SNMPtrapv1):
            result["pdu_type"] = "trap"
        else:
            result["pdu_type"] = "unknown"

    except Exception:
        pass

    return result if len(result) > 1 else None
