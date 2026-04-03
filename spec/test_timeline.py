"""Tests for device timeline builder."""
import pytest
from leetha.timeline import build_timeline


def test_empty_timeline():
    result = build_timeline(mac="aa:bb:cc:dd:ee:ff", device=None, observations=[], fingerprint_history=[], arp_history=[], findings=[])
    assert result == []


def test_first_seen_event():
    device = {"mac": "aa:bb:cc:dd:ee:ff", "first_seen": "2026-04-01T10:00:00", "hostname": "router"}
    result = build_timeline(mac="aa:bb:cc:dd:ee:ff", device=device, observations=[], fingerprint_history=[], arp_history=[], findings=[])
    assert len(result) == 1
    assert result[0]["type"] == "first_seen"


def test_observation_events():
    observations = [
        {"timestamp": "2026-04-01T10:05:00", "source_type": "dhcpv4", "raw_data": '{"hostname": "iPhone-5G"}', "confidence": 85},
        {"timestamp": "2026-04-01T10:03:00", "source_type": "arp", "raw_data": '{"src_ip": "192.168.1.50"}', "confidence": 30},
    ]
    result = build_timeline(mac="aa:bb:cc:dd:ee:ff", device=None, observations=observations, fingerprint_history=[], arp_history=[], findings=[])
    assert len(result) == 2
    assert result[0]["timestamp"] == "2026-04-01T10:05:00"  # sorted desc


def test_classification_change():
    history = [
        {"timestamp": "2026-04-01T10:10:00", "device_type": "smartphone", "manufacturer": "Apple", "os_family": "iOS", "hostname": "iPhone"},
        {"timestamp": "2026-04-01T10:05:00", "device_type": None, "manufacturer": None, "os_family": None, "hostname": None},
    ]
    result = build_timeline(mac="aa:bb:cc:dd:ee:ff", device=None, observations=[], fingerprint_history=history, arp_history=[], findings=[])
    assert len([e for e in result if e["type"] == "classification"]) == 2


def test_ip_change_events():
    arp = [
        {"ip": "192.168.1.50", "first_seen": "2026-04-01T10:00:00", "last_seen": "2026-04-01T10:30:00", "packet_count": 100},
        {"ip": "192.168.1.51", "first_seen": "2026-04-01T10:35:00", "last_seen": "2026-04-01T10:50:00", "packet_count": 50},
    ]
    result = build_timeline(mac="aa:bb:cc:dd:ee:ff", device=None, observations=[], fingerprint_history=[], arp_history=arp, findings=[])
    assert len([e for e in result if e["type"] == "ip_change"]) == 2


def test_finding_events():
    findings = [{"alert_type": "identity_shift", "severity": "critical", "message": "Vendor changed", "timestamp": "2026-04-01T10:15:00"}]
    result = build_timeline(mac="aa:bb:cc:dd:ee:ff", device=None, observations=[], fingerprint_history=[], arp_history=[], findings=findings)
    assert len([e for e in result if e["type"] == "finding"]) == 1
    assert "critical" in result[0]["detail"].lower()


def test_timeline_sorted_descending():
    device = {"mac": "aa:bb:cc:dd:ee:ff", "first_seen": "2026-04-01T10:00:00", "hostname": None}
    observations = [{"timestamp": "2026-04-01T10:05:00", "source_type": "arp", "raw_data": '{}', "confidence": 30}]
    findings = [{"alert_type": "new_device", "severity": "info", "message": "New device", "timestamp": "2026-04-01T10:01:00"}]
    result = build_timeline(mac="aa:bb:cc:dd:ee:ff", device=device, observations=observations, fingerprint_history=[], arp_history=[], findings=findings)
    timestamps = [e["timestamp"] for e in result]
    assert timestamps == sorted(timestamps, reverse=True)
