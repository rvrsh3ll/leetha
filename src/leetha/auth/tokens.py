"""Token generation and hashing utilities."""
from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

from leetha.config import _real_home

TOKEN_PREFIX = "ltk_"
_TOKEN_BYTES = 24  # 24 bytes = 48 hex chars
_TOKEN_FILENAME = "admin-token"


def generate_token() -> str:
    """Generate a new API token with the ltk_ prefix."""
    return TOKEN_PREFIX + secrets.token_hex(_TOKEN_BYTES)


def hash_token(raw_token: str) -> str:
    """Return the SHA-256 hex digest of a raw token string."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def save_admin_token(raw_token: str, leetha_dir: Path | None = None) -> Path:
    """Write raw admin token to ~/.leetha/admin-token with restricted permissions."""
    if leetha_dir is None:
        leetha_dir = _real_home() / ".leetha"
    leetha_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    token_file = leetha_dir / _TOKEN_FILENAME
    token_file.write_text(raw_token + "\n")
    token_file.chmod(0o600)
    return token_file


def load_admin_token(leetha_dir: Path | None = None) -> str | None:
    """Read raw admin token from ~/.leetha/admin-token, or None if missing."""
    if leetha_dir is None:
        leetha_dir = _real_home() / ".leetha"
    token_file = leetha_dir / _TOKEN_FILENAME
    if not token_file.exists():
        return None
    return token_file.read_text().strip()
