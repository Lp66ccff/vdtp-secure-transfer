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
from . import bucket as BK
from . import transfer as X
from .store import NAME_RE, Store, StoreError, resolve_user_path

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

BUCKETS: dict[str, BK.TokenBucket] = {}
PENDING_TTL = 600


def bucket_for(name: str, tier: str) -> BK.TokenBucket:
    rate = RATE_BPS.get(tier, RATE_BPS["free"])
    got = BUCKETS.get(name)
    if got is None or got.rate != rate:
        got = BK.TokenBucket(rate, burst=256 << 10)
        BUCKETS[name] = got
    return got


class RegisterBody(BaseModel):
    user: str
    pub: dict


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "proto": "VDTP/2", "ver": P.VER}


@app.post("/api/register")
async def register(body: RegisterBody) -> dict:
    if not NAME_RE.match(body.user or ""):
        raise HTTPException(status_code=400,
                            detail="用户名只允许字母、数字、下划线、连字符，1 到 32 位")
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
        self.streams: dict[int, object] = {}
        self.next_stream = 1
        self.send_lock = asyncio.Lock()
        self.ticket = ""
        self.bucket: BK.TokenBucket | None = None

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    async def send(self, ftype: int, payload: bytes = b"", *, stream: int = 0) -> None:
        async with self.send_lock:
            await self.ws.send_bytes(
                P.pack(ftype, payload, stream=stream, seq=self.next_seq()))

    async def send_json(self, ftype: int, obj: dict, *, stream: int = 0) -> None:
        await self.send(ftype, P.control(obj), stream=stream)

    async def error(self, code: str, msg: str, stream: int = 0) -> None:
        await self.send_json(P.T_ERROR, {"code": code, "msg": msg, "stream": stream},
                             stream=stream)


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
        parked = []
        for st in list(sess.streams.values()):
            if isinstance(st, X.Upload):
                if st.offset > 0:
                    parked.append(st.park())
                else:
                    st.abort()
            elif isinstance(st, X.Download) and st.task:
                st.task.cancel()
        if parked and sess.user:
            store.save_pending(sess.sid, sess.user["name"], json.dumps(parked),
                               time.time() + PENDING_TTL)
        sess.streams.clear()
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
        case P.T_OPEN:
            await on_open(sess, fr)
        case P.T_DATA:
            await on_data(sess, fr)
        case P.T_ACK:
            await on_ack(sess, fr)
        case P.T_DONE:
            await on_done(sess, fr)
        case P.T_DONE_OK:
            sess.streams.pop(fr.stream, None)
        case P.T_RESUME:
            await on_resume(sess, fr)
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
    sess.ticket = ticket
    sess.bucket = bucket_for(sess.user["name"], tier)
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
        if name.startswith("."):
            continue
        full = os.path.join(target, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        entries.append({"name": name, "size": st.st_size,
                        "dir": os.path.isdir(full), "mtime": int(st.st_mtime)})
    await sess.send_json(P.T_LIST_OK, {"path": body.get("path", ""), "entries": entries},
                         stream=fr.stream)


async def on_open(sess: Session, fr: P.Frame) -> None:
    assert sess.user is not None
    body = P.parse_control(fr.payload)
    mode = str(body.get("mode", "up"))
    root = store.user_root(sess.user["name"])
    rel = str(body.get("path", "")).strip("/")
    try:
        target = resolve_user_path(root, rel)
    except PermissionError as exc:
        await sess.error("DENIED", str(exc), stream=fr.stream)
        return

    if mode == "up":
        try:
            size = int(body.get("size", 0))
            declared = bytes.fromhex(str(body.get("root", "")))
        except (TypeError, ValueError):
            await sess.error("BAD_FRAME", "OPEN 字段不全", stream=fr.stream)
            return
        if size < 0 or size > X.MAX_FILE:
            await sess.error("DENIED", "文件超过 8 GiB", stream=fr.stream)
            return
        if size and len(declared) != 32:
            await sess.error("BAD_FRAME", "缺 Merkle 根", stream=fr.stream)
            return
        tier = sess.user["tier"]
        quota = QUOTA_BYTES.get(tier, QUOTA_BYTES["free"])
        used = store.user_usage(sess.user["name"])
        if os.path.exists(target) and not body.get("overwrite"):
            await sess.error("DENIED", "同名文件已存在，换名或带 overwrite 再传",
                             stream=fr.stream)
            return
        if used + size > quota:
            await sess.error("DENIED", f"超出配额：已用 {used}，本次 {size}，上限 {quota}",
                             stream=fr.stream)
            return
        stream = fr.stream or sess.next_stream
        if fr.stream and fr.stream in sess.streams:
            await sess.error("BAD_STREAM", "流号已被占用", stream=fr.stream)
            return
        sess.next_stream = max(sess.next_stream, stream) + 1
        parts = os.path.join(DATA_DIR, "parts")
        os.makedirs(parts, exist_ok=True)
        temp = os.path.join(parts, f"{sess.user['name']}-{sess.sid}-{stream}")
        sess.streams[stream] = X.Upload(stream, rel, target, temp, size, declared)
        await sess.send_json(P.T_OPEN_OK, {"stream": stream, "offset": 0, "size": size},
                             stream=stream)
        return

    if not os.path.isfile(target):
        await sess.error("NOT_FOUND", "文件不存在", stream=fr.stream)
        return
    if fr.stream and fr.stream in sess.streams:
        await sess.error("BAD_STREAM", "流号已被占用", stream=fr.stream)
        return
    stream = fr.stream or sess.next_stream
    sess.next_stream = max(sess.next_stream, stream) + 1
    dn = X.Download(stream, rel, target, os.path.getsize(target),
                    int(body.get("offset", 0) or 0))
    sess.streams[stream] = dn
    await sess.send_json(P.T_OPEN_OK, {"stream": stream, "offset": dn.offset, "size": dn.size},
                         stream=stream)
    dn.task = asyncio.create_task(X.pump(sess, dn, sess.bucket))


async def on_data(sess: Session, fr: P.Frame) -> None:
    st = sess.streams.get(fr.stream)
    if not isinstance(st, X.Upload):
        await sess.error("BAD_STREAM", "这条流不收数据", stream=fr.stream)
        return
    if len(fr.payload) < 8:
        await sess.error("BAD_FRAME", "DATA 缺偏移前缀", stream=fr.stream)
        return
    offset = int.from_bytes(fr.payload[:8], "big")
    if sess.bucket is not None:
        await sess.bucket.take(len(fr.payload) - 8)
    try:
        st.write(offset, fr.payload[8:])
    except X.TransferError as exc:
        await sess.error(exc.code, exc.msg, stream=fr.stream)
        st.abort()
        sess.streams.pop(st.id, None)
        return
    if st.offset - st.last_ack >= X.ACK_EVERY:
        st.last_ack = st.offset
        await sess.send_json(P.T_ACK, {"offset": st.offset}, stream=st.id)


async def on_ack(sess: Session, fr: P.Frame) -> None:
    st = sess.streams.get(fr.stream)
    if not isinstance(st, X.Download):
        return
    body = P.parse_control(fr.payload)
    st.ack(int(body.get("offset", 0)))


async def on_done(sess: Session, fr: P.Frame) -> None:
    st = sess.streams.get(fr.stream)
    body = P.parse_control(fr.payload)
    if isinstance(st, X.Upload):
        try:
            st.finish(int(body.get("size", -1)), str(body.get("sha256") or ""))
        except (X.TransferError, TypeError, ValueError) as exc:
            code = getattr(exc, "code", "BAD_FRAME")
            msg = getattr(exc, "msg", str(exc))
            st.abort()
            sess.streams.pop(st.id, None)
            await sess.error(code, msg, stream=fr.stream)
            return
        sess.streams.pop(st.id, None)
        await sess.send_json(P.T_DONE_OK, {"stream": st.id}, stream=st.id)
        return
    if isinstance(st, X.Download):
        sess.streams.pop(st.id, None)


async def on_resume(sess: Session, fr: P.Frame) -> None:
    assert sess.user is not None
    body = P.parse_control(fr.payload)
    payload = auth.verify_ticket(TICKET_SECRET, str(body.get("ticket", "")))
    if not payload or payload.get("user") != sess.user["name"]:
        await sess.error("RESUME_REJECTED", "票据无效或过期")
        return
    sid = str(payload.get("sid", ""))
    got = store.load_pending(sid, time.time())
    if not got:
        await sess.error("RESUME_REJECTED", "没有可恢复的会话")
        return
    store.drop_pending(sid)
    parked = {"user": got[0], "streams": json.loads(got[1])}
    streams = []
    for meta in parked["streams"]:
        if not os.path.exists(meta["temp"]):
            continue
        st = X.Upload(meta["stream"], meta["rel"], meta["final"], meta["temp"],
                      meta["size"], bytes.fromhex(meta["root"]), resume=True)
        sess.streams[st.id] = st
        sess.next_stream = max(sess.next_stream, st.id + 1)
        streams.append({"stream": st.id, "mode": "up", "path": st.rel,
                        "offset": st.offset, "size": st.size, "root": meta["root"]})
    await sess.send_json(P.T_RESUME_OK, {"sid": sess.sid, "streams": streams})


def main() -> None:  # pragma: no cover - 入口给 uvicorn 用
    import uvicorn

    host = os.environ.get("VDTP_HOST", "127.0.0.1")
    port = int(os.environ.get("VDTP_PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":  # pragma: no cover
    main()
