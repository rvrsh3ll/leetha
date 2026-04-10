import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from leetha.ui.web.app import fastapi_app
    import leetha.ui.web.app as web_app
    from leetha.capture.remote.server import RemoteSensorManager

    mock_app = MagicMock()
    mock_app._remote_sensor_manager = RemoteSensorManager()
    mock_app.config = MagicMock()
    mock_app.config.data_dir = "/tmp/leetha-test"
    web_app.app_instance = mock_app
    web_app._auth_enabled = False

    return TestClient(fastapi_app)


def test_get_targets(client):
    resp = client.get("/api/remote/targets")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 5
    names = [t["id"] for t in data]
    assert "linux-x86_64" in names
    assert "windows-x86_64" in names


def test_targets_have_required_fields(client):
    resp = client.get("/api/remote/targets")
    for target in resp.json():
        assert "id" in target
        assert "label" in target
        assert "default_buffer_mb" in target
        assert "triple" in target


@patch("leetha.capture.remote.build.check_prerequisites")
def test_check_prerequisites_endpoint(mock_check, client):
    mock_check.return_value = (True, "ok")
    resp = client.get("/api/remote/build/check?target=linux-x86_64")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


@patch("leetha.capture.remote.build.check_prerequisites")
def test_check_prerequisites_fails(mock_check, client):
    mock_check.return_value = (False, "cargo not found")
    resp = client.get("/api/remote/build/check?target=linux-arm64")
    assert resp.status_code == 200
    assert resp.json()["ok"] is False
    assert "cargo" in resp.json()["message"]
