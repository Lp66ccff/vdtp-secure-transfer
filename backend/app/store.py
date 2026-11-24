"""用户与文件元数据的存储。SQLite，查询一律参数化。

表结构随里程碑长，现在只有用户。
"""

from __future__ import annotations

import os
import re
import sqlite3
import time

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS pending (
    sid     TEXT PRIMARY KEY,
    user    TEXT NOT NULL,
    payload TEXT NOT NULL,
    expires REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    name       TEXT PRIMARY KEY,
    pubkey_jwk TEXT NOT NULL,
    tier       TEXT NOT NULL DEFAULT 'free',
    created    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     REAL NOT NULL,
    sid    TEXT,
    user   TEXT,
    event  TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);
"""


class StoreError(Exception):
    pass


def resolve_user_path(root: str, rel: str) -> str:
    """把请求里的相对路径钉在用户根目录内。越界抛 PermissionError。"""
    clean = (rel or "").strip("/")
    if "\x00" in clean:
        raise PermissionError("路径含空字节")
    target = os.path.realpath(os.path.join(root, clean))
    base = os.path.realpath(root)
    if target != base and not target.startswith(base + os.sep):
        raise PermissionError("路径越界")
    return target


class Store:
    def __init__(self, data_dir: str):
        self.data = os.path.abspath(data_dir)
        os.makedirs(self.data, exist_ok=True)
        self.db_path = os.path.join(self.data, "vdtp.db")
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---------------------------------------------------------------- 用户
    def user(self, name: str) -> dict | None:
        if not NAME_RE.match(name or ""):
            return None
        row = self.conn.execute(
            "SELECT name, pubkey_jwk, tier, created FROM users WHERE name = ?", (name,)
        ).fetchone()
        return dict(row) if row else None

    def register(self, name: str, jwk_json: str, tier: str = "free") -> bool:
        """新登记返回 True；同名同钥已存在返回 False；同名异钥抛 StoreError。"""
        if not NAME_RE.match(name or ""):
            raise StoreError("用户名只允许字母、数字、下划线和连字符，1 到 32 位")
        old = self.user(name)
        if old:
            if old["pubkey_jwk"] != jwk_json:
                raise StoreError("这个用户名已经登记了别的公钥")
            return False
        self.conn.execute(
            "INSERT INTO users (name, pubkey_jwk, tier, created) VALUES (?, ?, ?, ?)",
            (name, jwk_json, tier, time.time()),
        )
        self.conn.commit()
        return True

    # ---------------------------------------------------------------- 挂起的会话
    def save_pending(self, sid: str, name: str, payload: str, expires: float) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO pending (sid, user, payload, expires) VALUES (?, ?, ?, ?)",
            (sid, name, payload, expires))
        self.conn.commit()

    def load_pending(self, sid: str, now: float) -> tuple[str, str] | None:
        row = self.conn.execute(
            "SELECT user, payload, expires FROM pending WHERE sid = ?", (sid,)).fetchone()
        if not row or float(row["expires"]) < now:
            return None
        return row["user"], row["payload"]

    def drop_pending(self, sid: str) -> None:
        self.conn.execute("DELETE FROM pending WHERE sid = ?", (sid,))
        self.conn.commit()

    def sweep_pending(self, now: float) -> int:
        cur = self.conn.execute("DELETE FROM pending WHERE expires < ?", (now,))
        self.conn.commit()
        return cur.rowcount

    # ---------------------------------------------------------------- 审计
    def audit(self, event: str, *, user: str = "", sid: str = "", detail: str = "") -> None:
        self.conn.execute(
            "INSERT INTO audit (ts, sid, user, event, detail) VALUES (?, ?, ?, ?, ?)",
            (time.time(), sid, user, event, detail))
        self.conn.commit()

    def audit_tail(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ts, sid, user, event, detail FROM audit ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
        return [dict(r) for r in rows]

    def audit_count(self, event: str | None = None) -> int:
        if event is None:
            row = self.conn.execute("SELECT COUNT(*) AS n FROM audit").fetchone()
        else:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM audit WHERE event = ?", (event,)).fetchone()
        return int(row["n"])

    def set_tier(self, name: str, tier: str) -> bool:
        cur = self.conn.execute("UPDATE users SET tier = ? WHERE name = ?", (tier, name))
        self.conn.commit()
        return cur.rowcount > 0

    def user_usage(self, name: str) -> int:
        """用户目录里实际占用的字节数，隐藏文件（.part）不算。"""
        root = self.user_root(name)
        total = 0
        for dirpath, _dirs, files in os.walk(root):
            for filename in files:
                if filename.startswith("."):
                    continue
                try:
                    total += os.path.getsize(os.path.join(dirpath, filename))
                except OSError:
                    pass
        return total

    def user_root(self, name: str) -> str:
        root = os.path.join(self.data, "users", name)
        os.makedirs(root, exist_ok=True)
        return root
