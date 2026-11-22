"""VDTP/2 网关：WebSocket 端点、注册接口与目录列表。

现在的流程：HELLO → HELLO_ACK → AUTH_CHALLENGE → AUTH_RESPONSE → AUTH_OK，
之后能 LIST。传输在里程碑 3 接上。
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from . import auth, frame as P
from .store import Store, StoreError, resolve_user_path

DATA_DIR = os.environ.get("VDTP_DATA", "data")
HANDSHAKE_TIMEOUT = 5.0
HEARTBEAT_TIMEOUT = 120.0
TICKET_TTL = 3600
RATE_BPS = {"free": 2 << 20, "vip": 8 << 20}
QUOTA_BYTES = {"free": 512 << 20, "vip": 4 << 30}

app = FastAPI(title="VDTP/2 gateway", version="0.2.0")
store = Store(DATA_DIR)


def load_secret(path: str) -> bytes:
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read()
    secret = secrets.token_bytes(32)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(secret)
    return secret


TICKET_SECRET = load_secret(os.path.join(DATA_DIR, "ticket.key"))


class RegisterBody(BaseModel):
    user: str
    pub: dict


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "proto": "VDTP/2", "ver": P.VER}


@app.post("/api/register")
async def register(body: RegisterBody) -> dict:
    try:
        auth.jwk_to_public(body.pub)
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="公钥不合法，只收 EC P-256")
    canon = {k: body.pub[k] for k in ("kty", "crv", "x", "y")}
    jwk_json = json.dumps(canon, sort_keys=True, separators=(",", ":"))
    try:
        created = store.register(body.user, jwk_json)
    except StoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    store.user_root(body.user)
    return {"user": body.user, "created": created, "thumbprint": auth.thumbprint(canon)}


class Session:
    """一条连接上的协议状态：NEW → CHALLENGED → AUTHED。"""

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self.sid = secrets.token_hex(8)
        self.stage = "new"
        self.user: dict | None = None
        self.nonce = b""
        self.seq = 0
        self.started = time.time()

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    async def send(self, ftype: int, payload: bytes = b"", *, stream: int = 0) -> None:
        await self.ws.send_bytes(P.pack(ftype, payload, stream=stream, seq=self.next_seq()))

    async def send_json(self, ftype: int, obj: dict, *, stream: int = 0) -> None:
        await self.send(ftype, P.control(obj), stream=stream)

    async def error(self, code: str, msg: str, stream: int = 0) -> None:
        await self.send_json(P.T_ERROR, {"code": code, "msg": msg, "stream": stream})


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    sess = Session(ws)
    dec = P.FrameDecoder()

    try:
        while True:
            timeout = HANDSHAKE_TIMEOUT if sess.stage == "new" else HEARTBEAT_TIMEOUT
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=timeout)
            except asyncio.TimeoutError:
                await sess.error("TIMEOUT", "握手或心跳超时")
                break

            if msg.get("type") == "websocket.disconnect":
                break
            data = msg.get("bytes")
            if not data:
                await sess.error("BAD_FRAME", "只接受二进制帧")
                break

            for fr in dec.feed(data):
                if sess.stage == "new" and fr.type != P.T_HELLO:
                    await sess.error("AUTH_FAILED", "握手未完成，只接受 HELLO")
                    return
                await handle(sess, fr)
    except P.FrameError as exc:
        try:
            await sess.error(exc.code, str(exc))
        except RuntimeError:
            pass
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await ws.close()
        except RuntimeError:
            pass


async def handle(sess: Session, fr: P.Frame) -> None:
    need_auth = fr.type not in (P.T_HELLO, P.T_AUTH_RESPONSE, P.T_PING, P.T_BYE)
    if need_auth and sess.stage != "authed":
        await sess.error("AUTH_FAILED", "还没认证", stream=fr.stream)
        return

    match fr.type:
        case P.T_HELLO:
            await on_hello(sess, fr)
        case P.T_AUTH_RESPONSE:
            await on_auth_response(sess, fr)
        case P.T_PING:
            await sess.send(P.T_PONG)
        case P.T_LIST:
            await on_list(sess, fr)
        case P.T_BYE:
            raise WebSocketDisconnect(code=1000)
        case _:
            await sess.error("NOT_IMPLEMENTED", f"{fr.name} 还没实现", stream=fr.stream)


async def on_hello(sess: Session, fr: P.Frame) -> None:
    body = P.parse_control(fr.payload)
    if int(body.get("ver", 0)) != P.VER:
        await sess.error("BAD_FRAME", f"版本 {body.get('ver')} 不支持")
        return
    user = store.user(str(body.get("user", "")))
    if user is None:
        await sess.error("AUTH_FAILED", "用户未登记，先调用 /api/register")
        return
    sess.user = user
    sess.stage = "challenged"
    sess.nonce = secrets.token_bytes(32)
    await sess.send_json(P.T_HELLO_ACK, {"ver": P.VER, "sid": sess.sid})
    await sess.send_json(P.T_AUTH_CHALLENGE, {"nonce": sess.nonce.hex()})


async def on_auth_response(sess: Session, fr: P.Frame) -> None:
    if sess.stage != "challenged" or sess.user is None:
        await sess.error("AUTH_FAILED", "顺序不对，先发 HELLO")
        return
    body = P.parse_control(fr.payload)
    try:
        jwk = body["pub"]
        sig = auth.ub64u(str(body["sig"]))
    except (KeyError, ValueError):
        await sess.error("AUTH_FAILED", "AUTH_RESPONSE 字段不全")
        return

    stored = json.loads(sess.user["pubkey_jwk"])
    if auth.thumbprint(jwk) != auth.thumbprint(stored):
        await sess.error("AUTH_FAILED", "公钥与登记的不一致")
        return
    message = sess.nonce + sess.sid.encode()
    if not auth.verify_signature(jwk, message, sig):
        await sess.error("AUTH_FAILED", "挑战签名验不过")
        return

    tier = sess.user["tier"]
    sess.stage = "authed"
    ticket = auth.issue_ticket(TICKET_SECRET, {
        "sid": sess.sid,
        "user": sess.user["name"],
        "pub": auth.thumbprint(stored),
        "exp": int(time.time()) + TICKET_TTL,
    })
    await sess.send_json(P.T_AUTH_OK, {
        "user": sess.user["name"],
        "ticket": ticket,
        "rate": RATE_BPS.get(tier, RATE_BPS["free"]),
        "quota": QUOTA_BYTES.get(tier, QUOTA_BYTES["free"]),
    })


async def on_list(sess: Session, fr: P.Frame) -> None:
    assert sess.user is not None
    body = P.parse_control(fr.payload)
    root = store.user_root(sess.user["name"])
    try:
        target = resolve_user_path(root, str(body.get("path", "")))
    except PermissionError as exc:
        await sess.error("DENIED", str(exc), stream=fr.stream)
        return
    if not os.path.isdir(target):
        await sess.error("NOT_FOUND", "目录不存在", stream=fr.stream)
        return
    entries = []
    for name in sorted(os.listdir(target)):
        full = os.path.join(target, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        entries.append({"name": name, "size": st.st_size,
                        "dir": os.path.isdir(full), "mtime": int(st.st_mtime)})
    await sess.send_json(P.T_LIST_OK, {"path": body.get("path", ""), "entries": entries},
                         stream=fr.stream)


def main() -> None:  # pragma: no cover - 入口给 uvicorn 用
    import uvicorn

    host = os.environ.get("VDTP_HOST", "127.0.0.1")
    port = int(os.environ.get("VDTP_PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":  # pragma: no cover
    main()
