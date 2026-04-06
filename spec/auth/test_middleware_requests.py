"""Integration tests for auth middleware request flow."""
from unittest.mock import AsyncMock
from starlette.testclient import TestClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from leetha.auth.middleware import auth_middleware


def _make_app(*, db=None, auth_enabled=True):
    """Build a minimal Starlette app with the auth middleware."""

    async def protected(request: Request):
        role = request.scope.get("auth_role", "none")
        return JSONResponse({"role": role})

    async def middleware(request: Request, call_next):
        return await auth_middleware(
            request, call_next, db=db, auth_enabled=auth_enabled,
        )

    app = Starlette(
        routes=[Route("/api/test", protected)],
        middleware=[],
    )
    app.middleware("http")(middleware)
    return app


def test_db_none_returns_503():
    """When DB is None (startup), protected routes must return 503."""
    app = _make_app(db=None, auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test")
    assert resp.status_code == 503
    assert "initializing" in resp.json()["error"].lower()


def test_db_validate_throws_returns_503():
    """When db.validate_token() raises, protected routes must return 503."""
    mock_db = AsyncMock()
    mock_db.validate_token.side_effect = Exception("DB not initialized")
    app = _make_app(db=mock_db, auth_enabled=True)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/test", headers={"Authorization": "Bearer lta_faketoken123"})
    assert resp.status_code == 503
    assert "initializing" in resp.json()["error"].lower()


def test_health_exempt_when_db_none():
    """The /health path must remain accessible even when DB is None."""

    async def health_handler(request):
        return JSONResponse({"status": "ok", "ready": False})

    async def mw(request, call_next):
        return await auth_middleware(
            request, call_next, db=None, auth_enabled=True,
        )

    app = Starlette(routes=[Route("/health", health_handler)])
    app.middleware("http")(mw)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
