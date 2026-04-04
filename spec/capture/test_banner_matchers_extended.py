"""Tests for the 12 new protocol banner matchers."""

import struct

import pytest

from leetha.capture.banner.matchers import match_banner


# ---------------------------------------------------------------------------
# MQTT
# ---------------------------------------------------------------------------


class TestMQTT:
    def test_connack(self) -> None:
        payload = b"\x20\x02\x00\x00"
        result = match_banner("mqtt", payload)
        assert result is not None
        assert result["service"] == "mqtt"
        assert result["connect_return_code"] == 0

    def test_wrong_header_rejected(self) -> None:
        assert match_banner("mqtt", b"\x10\x02\x00\x00") is None

    def test_too_short_rejected(self) -> None:
        assert match_banner("mqtt", b"\x20\x02") is None


# ---------------------------------------------------------------------------
# SIP
# ---------------------------------------------------------------------------


class TestSIP:
    def test_response_with_server(self) -> None:
        payload = b"SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.0\r\n\r\n"
        result = match_banner("sip", payload)
        assert result is not None
        assert result["service"] == "sip"
        assert "Asterisk" in result["software"]

    def test_request_with_sip20(self) -> None:
        payload = b"INVITE sip:user@example.com SIP/2.0\r\n\r\n"
        result = match_banner("sip", payload)
        assert result is not None
        assert result["service"] == "sip"

    def test_non_sip_rejected(self) -> None:
        assert match_banner("sip", b"HTTP/1.1 200 OK\r\n\r\n") is None


# ---------------------------------------------------------------------------
# RTSP
# ---------------------------------------------------------------------------


class TestRTSP:
    def test_response_with_hikvision(self) -> None:
        payload = b"RTSP/1.0 200 OK\r\nServer: Hikvision-Webs\r\n\r\n"
        result = match_banner("rtsp", payload)
        assert result is not None
        assert result["service"] == "rtsp"
        assert "Hikvision" in result["software"]

    def test_non_rtsp_rejected(self) -> None:
        assert match_banner("rtsp", b"HTTP/1.1 200 OK\r\n\r\n") is None


# ---------------------------------------------------------------------------
# LDAP
# ---------------------------------------------------------------------------


class TestLDAP:
    def test_bind_response(self) -> None:
        # SEQUENCE(0x30) + length + msg_id + BindResponse(0x61) ...
        payload = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"
        result = match_banner("ldap", payload)
        assert result is not None
        assert result["service"] == "ldap"

    def test_search_result_done(self) -> None:
        payload = b"\x30\x0c\x02\x01\x01\x65\x07\x0a\x01\x00\x04\x00\x04\x00"
        result = match_banner("ldap", payload)
        assert result is not None
        assert result["service"] == "ldap"

    def test_wrong_tag_rejected(self) -> None:
        assert match_banner("ldap", b"\x31\x0c\x02\x01\x01\x61\x07") is None

    def test_no_app_tag_rejected(self) -> None:
        # SEQUENCE but no BindResponse or SearchResultDone tag
        assert match_banner("ldap", b"\x30\x0c\x02\x01\x01\x02\x07") is None


# ---------------------------------------------------------------------------
# Cassandra
# ---------------------------------------------------------------------------


class TestCassandra:
    def test_ready_response(self) -> None:
        # version=0x84 (response v4), flags=0, stream=0, opcode=0x02(READY)
        payload = b"\x84\x00\x00\x02\x00\x00\x00\x00"
        result = match_banner("cassandra", payload)
        assert result is not None
        assert result["service"] == "cassandra"

    def test_supported_response(self) -> None:
        payload = b"\x84\x00\x00\x06\x00\x00\x00\x00"
        result = match_banner("cassandra", payload)
        assert result is not None
        assert result["service"] == "cassandra"

    def test_request_rejected(self) -> None:
        # version=0x04 (request, not response -- no high bit)
        assert match_banner("cassandra", b"\x04\x00\x00\x02\x00\x00\x00\x00") is None

    def test_wrong_opcode_rejected(self) -> None:
        assert match_banner("cassandra", b"\x84\x00\x00\x0a\x00\x00\x00\x00") is None


# ---------------------------------------------------------------------------
# Elasticsearch
# ---------------------------------------------------------------------------


class TestElasticsearch:
    def test_cluster_response(self) -> None:
        payload = b'HTTP/1.1 200 OK\r\n\r\n{"cluster_name":"test","version":{"number":"8.12.0"}}'
        result = match_banner("elasticsearch", payload)
        assert result is not None
        assert result["service"] == "elasticsearch"
        assert result["version"] == "8.12.0"
        assert result["software"] == "Elasticsearch"

    def test_no_cluster_name_rejected(self) -> None:
        payload = b'HTTP/1.1 200 OK\r\n\r\n{"status":"ok"}'
        assert match_banner("elasticsearch", payload) is None

    def test_non_http_rejected(self) -> None:
        payload = b'{"cluster_name":"test"}'
        assert match_banner("elasticsearch", payload) is None


# ---------------------------------------------------------------------------
# AMQP
# ---------------------------------------------------------------------------


class TestAMQP:
    def test_protocol_header(self) -> None:
        payload = b"AMQP\x00\x00\x09\x01"
        result = match_banner("amqp", payload)
        assert result is not None
        assert result["service"] == "amqp"
        assert result["proto_version"] == "0.9.1"

    def test_method_frame(self) -> None:
        payload = b"\x01\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x0a" + b"\x00" * 5
        result = match_banner("amqp", payload)
        assert result is not None
        assert result["service"] == "amqp"

    def test_random_bytes_rejected(self) -> None:
        assert match_banner("amqp", b"\x55\x44\x33\x22") is None


# ---------------------------------------------------------------------------
# Docker API
# ---------------------------------------------------------------------------


class TestDockerAPI:
    def test_api_version_response(self) -> None:
        payload = b'HTTP/1.1 200 OK\r\n\r\n{"ApiVersion":"1.45","Os":"linux"}'
        result = match_banner("docker_api", payload)
        assert result is not None
        assert result["service"] == "docker_api"
        assert result["version"] == "1.45"
        assert result["software"] == "Docker"

    def test_no_api_version_rejected(self) -> None:
        payload = b'HTTP/1.1 200 OK\r\n\r\n{"status":"ok"}'
        assert match_banner("docker_api", payload) is None


# ---------------------------------------------------------------------------
# Kubernetes API
# ---------------------------------------------------------------------------


class TestKubernetesAPI:
    def test_version_response(self) -> None:
        payload = b'HTTP/1.1 200 OK\r\n\r\n{"major":"1","minor":"28","gitVersion":"v1.28.0"}'
        result = match_banner("kubernetes_api", payload)
        assert result is not None
        assert result["service"] == "kubernetes_api"
        assert result["software"] == "Kubernetes"
        assert result["version"] == "v1.28.0"

    def test_status_response(self) -> None:
        payload = b'HTTP/1.1 403 Forbidden\r\n\r\n{"kind": "Status","code":403}'
        result = match_banner("kubernetes_api", payload)
        assert result is not None
        assert result["service"] == "kubernetes_api"

    def test_non_k8s_http_rejected(self) -> None:
        payload = b'HTTP/1.1 200 OK\r\n\r\n{"hello":"world"}'
        assert match_banner("kubernetes_api", payload) is None


# ---------------------------------------------------------------------------
# SOCKS
# ---------------------------------------------------------------------------


class TestSOCKS:
    def test_socks5_no_auth(self) -> None:
        payload = b"\x05\x00"
        result = match_banner("socks", payload)
        assert result is not None
        assert result["service"] == "socks"
        assert result["version"] == "5"

    def test_socks4_granted(self) -> None:
        payload = b"\x00\x5a\x00\x00\x00\x00\x00\x00"
        result = match_banner("socks", payload)
        assert result is not None
        assert result["service"] == "socks"
        assert result["version"] == "4"

    def test_random_bytes_rejected(self) -> None:
        assert match_banner("socks", b"\x03\x01") is None

    def test_too_short_rejected(self) -> None:
        assert match_banner("socks", b"\x05") is None


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------


class TestBGP:
    def test_open_message(self) -> None:
        # 16 bytes marker + 2 bytes length + type=1 + version=4 + AS=200
        marker = b"\xff" * 16
        length = b"\x00\x1d"
        msg_type = b"\x01"
        version = b"\x04"
        as_number = struct.pack("!H", 200)
        payload = marker + length + msg_type + version + as_number + b"\x00" * 8
        result = match_banner("bgp", payload)
        assert result is not None
        assert result["service"] == "bgp"
        assert result["version"] == "4"
        assert result["as_number"] == 200

    def test_wrong_marker_rejected(self) -> None:
        payload = b"\x00" * 16 + b"\x00\x1d\x01\x04\x00\xc8"
        assert match_banner("bgp", payload) is None

    def test_wrong_type_rejected(self) -> None:
        payload = b"\xff" * 16 + b"\x00\x1d\x02\x04\x00\xc8"
        assert match_banner("bgp", payload) is None

    def test_too_short_rejected(self) -> None:
        assert match_banner("bgp", b"\xff" * 16 + b"\x00\x1d") is None


# ---------------------------------------------------------------------------
# PPTP
# ---------------------------------------------------------------------------


class TestPPTP:
    def test_start_control_reply(self) -> None:
        payload = b"\x00" * 8 + b"\x00\x01\x00\x02" + b"\x00" * 20
        result = match_banner("pptp", payload)
        assert result is not None
        assert result["service"] == "pptp"

    def test_wrong_msg_type_rejected(self) -> None:
        payload = b"\x00" * 8 + b"\x00\x02\x00\x02" + b"\x00" * 20
        assert match_banner("pptp", payload) is None

    def test_wrong_ctrl_type_rejected(self) -> None:
        payload = b"\x00" * 8 + b"\x00\x01\x00\x03" + b"\x00" * 20
        assert match_banner("pptp", payload) is None

    def test_too_short_rejected(self) -> None:
        assert match_banner("pptp", b"\x00" * 8 + b"\x00\x01") is None


# ---------------------------------------------------------------------------
# Negative: empty payload always returns None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("service", [
    "mqtt", "sip", "rtsp", "ldap", "cassandra", "elasticsearch",
    "amqp", "docker_api", "kubernetes_api", "socks", "bgp", "pptp",
])
def test_empty_payload_returns_none(service: str) -> None:
    assert match_banner(service, b"") is None
