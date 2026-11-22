"""用户存储与路径越界的单元测试。"""

from __future__ import annotations

import json
import pathlib

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


def test_user_usage_counts_files(tmp_path):
    store = Store(str(tmp_path))
    root = pathlib.Path(store.user_root("alice"))
    (root / "a.bin").write_bytes(b"x" * 100)
    (root / "sub").mkdir()
    (root / "sub" / "b.bin").write_bytes(b"y" * 50)
    (root / ".part-abc").write_bytes(b"z" * 500)   # 半成品不算
    assert store.user_usage("alice") == 150


def test_pending_roundtrip(tmp_path):
    store = Store(str(tmp_path))
    store.save_pending("sid1", "alice", '[{"offset": 1024}]', 9e9)
    assert store.load_pending("sid1", 1.0) == ("alice", '[{"offset": 1024}]')
    assert store.load_pending("sid1", 1e10) is None      # 过期
    store.drop_pending("sid1")
    assert store.load_pending("sid1", 1.0) is None


def test_pending_sweep(tmp_path):
    store = Store(str(tmp_path))
    store.save_pending("old", "alice", "[]", 1.0)
    store.save_pending("new", "alice", "[]", 9e9)
    assert store.sweep_pending(2.0) == 1
    assert store.load_pending("new", 3.0) is not None
