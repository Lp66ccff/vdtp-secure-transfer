"""连接与流上限的单元测试。"""

from __future__ import annotations

from app.limits import Limits


def test_ip_cap_and_release():
    lim = Limits(per_ip=2, per_user=4, total=10)
    assert lim.open_conn("10.0.0.1") and lim.open_conn("10.0.0.1")
    assert not lim.open_conn("10.0.0.1")
    assert lim.open_conn("10.0.0.2")
    lim.close_conn("10.0.0.1")
    assert lim.open_conn("10.0.0.1")


def test_total_cap_counts_all_ips():
    lim = Limits(per_ip=5, per_user=4, total=2)
    assert lim.open_conn("a") and lim.open_conn("b")
    assert not lim.open_conn("c")
    lim.close_conn("a")
    assert lim.open_conn("c")
    assert lim.snapshot()["live"] == 2


def test_user_cap_and_release():
    lim = Limits(per_ip=8, per_user=2, total=8)
    assert lim.open_user("alice") and lim.open_user("alice")
    assert not lim.open_user("alice")
    lim.close_user("alice")
    assert lim.open_user("alice")
    lim.close_user("alice")
    lim.close_user("alice")
    assert lim.snapshot()["users"] == 0


def test_double_release_is_harmless():
    lim = Limits()
    lim.open_conn("a")
    lim.close_conn("a")
    lim.close_conn("a")
    lim.close_user("nobody")
    assert lim.snapshot() == {"live": 0, "ips": 0, "users": 0}


def test_stream_cap_value():
    assert Limits().streams == 8
