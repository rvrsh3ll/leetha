"""Role-based access control definitions."""
from __future__ import annotations

ADMIN_ONLY_PREFIXES = (
    "/api/auth/tokens",
    "/api/auth/revoke",
    "/api/capture/restart",
    "/api/settings/db",
    "/api/settings/import",
    "/api/settings/query",
)

ADMIN_ONLY_METHODS: dict[str, tuple[str, ...]] = {
    "PUT": ("/api/settings",),
    "DELETE": ("/api/alerts", "/api/trust", "/api/suppressions", "/api/patterns"),
    "POST": ("/api/settings/apply", "/api/settings/reset"),
}


def requires_admin(method: str, path: str) -> bool:
    """Return True if this method+path combination requires admin role."""
    for prefix in ADMIN_ONLY_PREFIXES:
        if path.startswith(prefix):
            return True
    method_prefixes = ADMIN_ONLY_METHODS.get(method.upper(), ())
    for prefix in method_prefixes:
        if path.startswith(prefix):
            return True
    return False
