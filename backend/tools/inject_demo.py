"""注入演示：拿常见载荷打注册接口与路径检查，看服务端怎么挡。

    python3 tools/inject_demo.py [http://127.0.0.1:8000]

先登记一个正常用户，再用合法公钥配注入式的用户名去打，这样挡下来的是用户名白名单，
不是“公钥不合法”。打完核对：这个用户还在、表里行数没变。
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import urllib.error
import urllib.request

sys.path.insert(0, ".")

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from app import auth  # noqa: E402
from app.paths import data_dir
from app.store import Store, resolve_user_path  # noqa: E402

PAYLOADS = [
    "alice' OR 1=1--",
    "'; DROP TABLE users; --",
    "' UNION SELECT name, pubkey_jwk FROM users --",
    "admin'--",
    "1; DELETE FROM users",
]


def new_jwk() -> dict:
    nums = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": auth.b64u(nums.x.to_bytes(32, "big")),
            "y": auth.b64u(nums.y.to_bytes(32, "big"))}


def post(base: str, path: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except json.JSONDecodeError:
            return exc.code, {}


def main(base: str) -> int:
    store = Store(data_dir())
    name = "demo-" + secrets.token_hex(3)
    jwk = new_jwk()
    status, body = post(base, "/api/register", {"user": name, "pub": jwk})
    print(f"登记正常用户 {name} -> {status} {body.get('created')}")
    rows = store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    print(f"表里现在 {rows} 行\n")

    print("== 注册接口：合法公钥 + 注入式用户名")
    blocked = 0
    for payload in PAYLOADS:
        status, body = post(base, "/api/register", {"user": payload, "pub": jwk})
        detail = body.get("detail", "")
        if status == 400:
            blocked += 1
        print(f"  {payload!r:45s} -> {status} {detail}")

    rows_after = store.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    alive = store.user(name) is not None
    print(f"\n打完：{blocked}/{len(PAYLOADS)} 条被用户名白名单挡下；"
          f"行数 {rows} -> {rows_after}；{name} {'仍在' if alive else '没了'}")

    print("\n== 路径：LIST 用的是同一份钉根函数")
    root = store.user_root(name)
    for path in ["../", "../../etc/passwd", "docs/../../bob"]:
        try:
            print(f"  {path!r:22s} -> {resolve_user_path(root, path)}")
        except PermissionError as exc:
            print(f"  {path!r:22s} -> 拒绝：{exc}")

    ok = blocked == len(PAYLOADS) and rows_after == rows and alive
    print("\n结论：用户名走白名单正则，查询全部参数化，路径经 realpath 钉在用户根目录。"
          + ("" if ok else "（有不符项，看上面几行）"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"))
