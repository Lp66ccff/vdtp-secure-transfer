"""用户存储与路径越界的单元测试。"""

from __future__ import annotations

import json

import pytest

from app.store import Store, StoreError, resolve_user_path

JWK = json.dumps({"kty": "EC", "crv": "P-256", "x": "AA", "y": "BB"}, sort_keys=True)
OTHER = json.dumps({"kty": "EC", "crv": "P-256", "x": "CC", "y": "DD"}, sort_keys=True)


def test_register_and_lookup(tmp_path):
    store = Store(str(tmp_path))
    assert store.register("alice", JWK) is True
    assert store.user("alice")["pubkey_jwk"] == JWK
    assert store.user("nobody") is None


def test_same_key_twice_is_not_created(tmp_path):
    store = Store(str(tmp_path))
    store.register("alice", JWK)
    assert store.register("alice", JWK) is False


def test_other_key_on_same_name_conflicts(tmp_path):
    store = Store(str(tmp_path))
    store.register("alice", JWK)
    with pytest.raises(StoreError):
        store.register("alice", OTHER)


def test_bad_names_rejected(tmp_path):
    store = Store(str(tmp_path))
    for name in ["", "../etc", "a b", "a/b", "x" * 33, "中文"]:
        with pytest.raises(StoreError):
            store.register(name, JWK)
        assert store.user(name) is None


def test_injection_style_name_is_not_a_user(tmp_path):
    store = Store(str(tmp_path))
    store.register("alice", JWK)
    assert store.user("alice' OR 1=1--") is None
    assert store.user("'; DROP TABLE users; --") is None
    assert store.user("alice") is not None  # 表还在


def test_user_root_is_created(tmp_path):
    store = Store(str(tmp_path))
    root = store.user_root("alice")
    assert root.endswith("/users/alice")


def test_resolve_stays_inside_root(tmp_path):
    root = tmp_path / "alice"
    root.mkdir()
    assert resolve_user_path(str(root), "") == str(root.resolve())
    assert resolve_user_path(str(root), "docs/a.txt") == str((root / "docs/a.txt").resolve())


def test_resolve_blocks_traversal(tmp_path):
    root = tmp_path / "alice"
    root.mkdir()
    (tmp_path / "bob").mkdir()
    for bad in ["../bob", "../../etc/passwd", "docs/../../bob"]:
        with pytest.raises(PermissionError):
            resolve_user_path(str(root), bad)


def test_absolute_path_is_taken_relative_to_root(tmp_path):
    root = tmp_path / "alice"
    root.mkdir()
    assert resolve_user_path(str(root), "/etc/passwd") == str((root / "etc/passwd").resolve())
    assert resolve_user_path(str(root), "/") == str(root.resolve())
