"""Tests for auth middleware logic."""
from leetha.auth.middleware import check_auth_required, EXEMPT_PATHS, EXEMPT_PREFIXES


def test_localhost_no_auth():
    assert check_auth_required("127.0.0.1") is False


def test_localhost_ipv6_no_auth():
    assert check_auth_required("::1") is False


def test_wildcard_requires_auth():
    assert check_auth_required("0.0.0.0") is True


def test_lan_ip_requires_auth():
    assert check_auth_required("192.168.1.50") is True


def test_force_auth_on():
    assert check_auth_required("127.0.0.1", force_auth=True) is True


def test_force_auth_off():
    assert check_auth_required("0.0.0.0", force_auth=False) is False


def test_exempt_paths():
    assert "/api/auth/login" in EXEMPT_PATHS
    assert "/health" in EXEMPT_PATHS


def test_exempt_prefixes():
    assert "/assets/" in EXEMPT_PREFIXES
