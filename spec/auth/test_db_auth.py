"""Tests for auth_tokens database operations."""
import pytest
from pathlib import Path
from leetha.store.database import Database
from leetha.auth.tokens import generate_token, hash_token


@pytest.fixture
async def db(tmp_path):
    d = Database(tmp_path / "test.db")
    await d.initialize()
    yield d
    await d.close()


async def test_create_auth_token(db):
    token = generate_token()
    token_id = await db.create_auth_token(hash_token(token), role="admin", label="test")
    assert token_id > 0


async def test_validate_token_hash(db):
    token = generate_token()
    await db.create_auth_token(hash_token(token), role="admin", label="test")
    result = await db.validate_token(hash_token(token))
    assert result is not None
    assert result["role"] == "admin"
    assert result["label"] == "test"
    assert result["revoked"] == 0


async def test_validate_token_invalid(db):
    result = await db.validate_token("nonexistent_hash")
    assert result is None


async def test_validate_revoked_token(db):
    token = generate_token()
    token_id = await db.create_auth_token(hash_token(token), role="admin")
    await db.revoke_auth_token(token_id)
    result = await db.validate_token(hash_token(token))
    assert result is None


async def test_list_auth_tokens(db):
    t1 = generate_token()
    t2 = generate_token()
    await db.create_auth_token(hash_token(t1), role="admin", label="admin-key")
    await db.create_auth_token(hash_token(t2), role="analyst", label="analyst-key")
    tokens = await db.list_auth_tokens()
    assert len(tokens) == 2
    roles = {t["role"] for t in tokens}
    assert roles == {"admin", "analyst"}


async def test_update_last_used(db):
    token = generate_token()
    await db.create_auth_token(hash_token(token), role="admin")
    result = await db.validate_token(hash_token(token))
    assert result["last_used"] is not None


async def test_count_active_admin_tokens(db):
    assert await db.count_active_admin_tokens() == 0
    token = generate_token()
    await db.create_auth_token(hash_token(token), role="admin")
    assert await db.count_active_admin_tokens() == 1


async def test_revoke_all_admin_tokens(db):
    t1 = generate_token()
    t2 = generate_token()
    await db.create_auth_token(hash_token(t1), role="admin")
    await db.create_auth_token(hash_token(t2), role="admin")
    assert await db.count_active_admin_tokens() == 2
    await db.revoke_all_admin_tokens()
    assert await db.count_active_admin_tokens() == 0
