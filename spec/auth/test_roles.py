"""Tests for role-based access control."""
from leetha.auth.roles import requires_admin


def test_admin_settings_write():
    assert requires_admin("PUT", "/api/settings")


def test_admin_capture_restart():
    assert requires_admin("POST", "/api/capture/restart")


def test_admin_delete_alerts():
    assert requires_admin("DELETE", "/api/alerts/all")


def test_admin_auth_create():
    assert requires_admin("POST", "/api/auth/tokens")


def test_analyst_read_devices():
    assert not requires_admin("GET", "/api/devices")


def test_analyst_read_alerts():
    assert not requires_admin("GET", "/api/alerts")


def test_analyst_acknowledge_alert():
    assert not requires_admin("POST", "/api/alerts/bulk")


def test_analyst_read_stats():
    assert not requires_admin("GET", "/api/stats")
