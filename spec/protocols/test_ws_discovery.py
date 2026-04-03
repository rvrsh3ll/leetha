"""Tests for WS-Discovery parser."""
import pytest
from leetha.capture.protocols.ws_discovery import (
    parse_ws_discovery, _extract_action, _extract_types,
    _extract_pnp_metadata, _NS,
)
import xml.etree.ElementTree as ET


# --- Helper: build a minimal WSD Hello XML ---
def _hello_xml(types="wprt:PrinterServiceType", manufacturer="HP", model="LaserJet"):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:pnp="http://schemas.microsoft.com/windows/pnpx/2005/10">
  <s:Header>
    <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</a:Action>
  </s:Header>
  <s:Body>
    <d:Hello>
      <d:Types>{types}</d:Types>
      <d:Scopes>http://example.com/scope</d:Scopes>
      <d:XAddrs>http://192.168.1.100:80/ws</d:XAddrs>
      <pnp:Manufacturer>{manufacturer}</pnp:Manufacturer>
      <pnp:ModelName>{model}</pnp:ModelName>
    </d:Hello>
  </s:Body>
</s:Envelope>"""


def test_extract_action_hello():
    root = ET.fromstring(_hello_xml())
    assert _extract_action(root) == "hello"


def test_extract_types_printer():
    root = ET.fromstring(_hello_xml(types="wprt:PrinterServiceType"))
    types = _extract_types(root)
    assert "printer" in types


def test_extract_pnp_metadata():
    root = ET.fromstring(_hello_xml(manufacturer="HP", model="LaserJet Pro"))
    meta = _extract_pnp_metadata(root)
    assert meta["manufacturer"] == "HP"
    assert meta["model"] == "LaserJet Pro"


def test_parse_returns_none_for_non_udp():
    """Non-UDP packets return None."""
    from unittest.mock import MagicMock
    pkt = MagicMock()
    pkt.haslayer.return_value = False
    assert parse_ws_discovery(pkt) is None


def test_parse_returns_none_for_wrong_port():
    """UDP packets on wrong port return None."""
    from unittest.mock import MagicMock
    pkt = MagicMock()
    pkt.haslayer.return_value = True
    pkt.__getitem__ = lambda self, k: MagicMock(dport=80, sport=12345)
    assert parse_ws_discovery(pkt) is None
