"""Tests for SNMP parser VarBind extraction."""
from __future__ import annotations

import pytest
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.snmp import (
    SNMP,
    SNMPget,
    SNMPresponse,
    SNMPvarbind,
)
from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING

from leetha.capture.parsers.snmp import parse_snmp


def _make_snmp_response(varbinds, community=b"public", version=1):
    """Build an Ethernet/IP/UDP/SNMP GetResponse packet."""
    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=161, dport=41234)
        / SNMP(
            version=version,
            community=community,
            PDU=SNMPresponse(varbindlist=varbinds),
        )
    )
    return pkt


class TestSNMPVarBindExtraction:
    """Verify that sysDescr, sysName, sysObjectID are extracted."""

    def test_sys_descr_extracted(self):
        pkt = _make_snmp_response([
            SNMPvarbind(
                oid=ASN1_OID("1.3.6.1.2.1.1.1.0"),
                value=ASN1_STRING(b"Cisco IOS Software, C3750 Software"),
            ),
        ])
        result = parse_snmp(pkt)
        assert result is not None
        assert result["pdu_type"] == "get-response"
        assert result["sys_descr"] == "Cisco IOS Software, C3750 Software"

    def test_sys_name_extracted(self):
        pkt = _make_snmp_response([
            SNMPvarbind(
                oid=ASN1_OID("1.3.6.1.2.1.1.5.0"),
                value=ASN1_STRING(b"switch01.example.com"),
            ),
        ])
        result = parse_snmp(pkt)
        assert result is not None
        assert result["sys_name"] == "switch01.example.com"

    def test_sys_object_id_extracted(self):
        pkt = _make_snmp_response([
            SNMPvarbind(
                oid=ASN1_OID("1.3.6.1.2.1.1.2.0"),
                value=ASN1_OID("1.3.6.1.4.1.9.1.516"),
            ),
        ])
        result = parse_snmp(pkt)
        assert result is not None
        assert result["sys_object_id"] == "1.3.6.1.4.1.9.1.516"

    def test_multiple_varbinds(self):
        pkt = _make_snmp_response([
            SNMPvarbind(
                oid=ASN1_OID("1.3.6.1.2.1.1.1.0"),
                value=ASN1_STRING(b"Linux server 5.15.0"),
            ),
            SNMPvarbind(
                oid=ASN1_OID("1.3.6.1.2.1.1.5.0"),
                value=ASN1_STRING(b"web01.local"),
            ),
            SNMPvarbind(
                oid=ASN1_OID("1.3.6.1.2.1.1.6.0"),
                value=ASN1_STRING(b"Server Room A"),
            ),
        ])
        result = parse_snmp(pkt)
        assert result is not None
        assert result["sys_descr"] == "Linux server 5.15.0"
        assert result["sys_name"] == "web01.local"
        assert result["sys_location"] == "Server Room A"

    def test_oid_without_trailing_zero(self):
        """OIDs without .0 suffix should also match."""
        pkt = _make_snmp_response([
            SNMPvarbind(
                oid=ASN1_OID("1.3.6.1.2.1.1.1"),
                value=ASN1_STRING(b"Juniper Junos"),
            ),
        ])
        result = parse_snmp(pkt)
        assert result is not None
        assert result["sys_descr"] == "Juniper Junos"

    def test_get_request_no_varbind_extraction(self):
        """GetRequest packets should not attempt VarBind value extraction."""
        pkt = (
            Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=41234, dport=161)
            / SNMP(
                version=1,
                community=b"public",
                PDU=SNMPget(varbindlist=[
                    SNMPvarbind(
                        oid=ASN1_OID("1.3.6.1.2.1.1.1.0"),
                    ),
                ]),
            )
        )
        result = parse_snmp(pkt)
        assert result is not None
        assert result["pdu_type"] == "get-request"
        assert "sys_descr" not in result

    def test_community_and_version_still_extracted(self):
        pkt = _make_snmp_response(
            [
                SNMPvarbind(
                    oid=ASN1_OID("1.3.6.1.2.1.1.1.0"),
                    value=ASN1_STRING(b"test"),
                ),
            ],
            community=b"secretcommunity",
            version=1,
        )
        result = parse_snmp(pkt)
        assert result is not None
        assert result["community"] == "secretcommunity"
        assert result["version"] == "v2c"

    def test_unrecognized_oids_ignored(self):
        pkt = _make_snmp_response([
            SNMPvarbind(
                oid=ASN1_OID("1.3.6.1.2.1.2.1.0"),
                value=ASN1_STRING(b"some interface count"),
            ),
        ])
        result = parse_snmp(pkt)
        assert result is not None
        assert "sys_descr" not in result
        assert "sys_name" not in result
