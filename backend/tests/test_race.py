"""两路真连接的竞态用例：起一个 uvicorn 子进程，开两条 WebSocket 同时打。

不打桩：服务端是真的 uvicorn，客户端是真的 websockets，帧走真 socket。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from websockets.asyncio.client import connect

from app import auth, frame as P
from app import merkle

CHUNK = 256 << 10


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    data = tmp_path_factory.mktemp("vdtp")
    port = free_port()
    env = dict(os.environ, VDTP_DATA=str(data), VDTP_HOST="127.0.0.1", VDTP_PORT=str(port))
    backend = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
         "--port", str(port), "--log-level", "warning"],
        cwd=backend, env=env)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/api/health", timeout=0.5).read()
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("uvicorn 没起来")
        yield base, str(data)
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def make_identity():
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256",
           "x": auth.b64u(nums.x.to_bytes(32, "big")),
           "y": auth.b64u(nums.y.to_bytes(32, "big"))}
    return key, jwk


def sign_raw(key, message: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def register(base: str, user: str, jwk: dict) -> None:
    body = json.dumps({"user": user, "pub": jwk}).encode()
    req = urllib.request.Request(base + "/api/register", data=body,
                                 headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5).read()


async def recv(ws, dec: P.FrameDecoder, timeout: float = 5) -> P.Frame:
    while True:
        frames = dec.feed(await asyncio.wait_for(ws.recv(), timeout=timeout))
        if frames:
            return frames[0]


class Conn:
    def __init__(self, ws, dec, seq: int):
        self.ws = ws
        self.dec = dec
        self.seq = seq

    def nxt(self) -> int:
        self.seq += 1
        return self.seq

    async def close(self):
        await self.ws.close()


async def login(base: str, user: str, key=None, jwk=None) -> Conn:
    if key is None:
        key, jwk = make_identity()
        register(base, user, jwk)
    ws = await connect(base.replace("http://", "ws://") + "/ws", max_size=8 << 20)
    dec = P.FrameDecoder()
    c = Conn(ws, dec, 0)
    await ws.send(P.pack(P.T_HELLO, P.control({"ver": P.VER, "user": user}), seq=c.nxt()))
    ack = P.parse_control((await recv(ws, dec)).payload)
    chal = P.parse_control((await recv(ws, dec)).payload)
    msg = bytes.fromhex(chal["nonce"]) + ack["sid"].encode()
    await ws.send(P.pack(P.T_AUTH_RESPONSE,
                         P.control({"pub": jwk, "sig": auth.b64u(sign_raw(key, msg))}),
                         seq=c.nxt()))
    fr = await recv(ws, dec)
    assert fr.type == P.T_AUTH_OK, fr.name
    return c


async def open_up(c: Conn, path: str, payload: bytes) -> int:
    chunks = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)]
    root = merkle.root_of([merkle.leaf(ch) for ch in chunks])
    await c.ws.send(P.pack(P.T_OPEN, P.control({
        "path": path, "mode": "up", "size": len(payload), "root": root.hex()}), seq=c.nxt()))
    fr = await recv(c.ws, c.dec)
    assert fr.type == P.T_OPEN_OK, fr.name
    return fr.stream


async def send_chunk(c: Conn, stream: int, offset: int, chunk: bytes) -> None:
    await c.ws.send(P.pack(P.T_DATA, P.data(offset, chunk), stream=stream, seq=c.nxt()))


async def finish_up(c: Conn, stream: int, size: int) -> None:
    await c.ws.send(P.pack(P.T_DONE, P.control({"size": size}), stream=stream, seq=c.nxt()))


async def wait_done(c: Conn, streams: set[int], limit: int = 50) -> set[int]:
    got = set()
    for _ in range(limit):
        fr = await recv(c.ws, c.dec)
        if fr.type == P.T_DONE_OK:
            got.add(fr.stream)
            if got >= streams:
                return got
        if fr.type == P.T_ERROR:
            body = P.parse_control(fr.payload)
            raise AssertionError(f"{body['code']}: {body['msg']}")
    raise AssertionError(f"没收齐 DONE_OK：{got} / {streams}")


async def upload_one(base: str, user: str, name: str, payload: bytes, key, jwk) -> bytes:
    c = await login(base, user, key, jwk)
    try:
        stream = await open_up(c, name, payload)
        for off in range(0, len(payload), CHUNK):
            await send_chunk(c, stream, off, payload[off:off + CHUNK])
        await finish_up(c, stream, len(payload))
        await wait_done(c, {stream})
    finally:
        await c.close()
    return payload


@pytest.mark.asyncio
async def test_two_streams_interleaved_in_one_connection(server):
    """一条连接两条流交错发块，各自落盘、摘要都对。"""
    base, data = server
    user = "race-" + secrets.token_hex(3)
    a, b = os.urandom(3 * CHUNK), os.urandom(2 * CHUNK)
    c = await login(base, user)
    try:
        sa = await open_up(c, "a.bin", a)
        sb = await open_up(c, "b.bin", b)
        assert sa != sb
        rounds = max(len(a), len(b)) // CHUNK + 1
        for i in range(rounds):
            if i * CHUNK < len(a):
                await send_chunk(c, sa, i * CHUNK, a[i * CHUNK:(i + 1) * CHUNK])
            if i * CHUNK < len(b):
                await send_chunk(c, sb, i * CHUNK, b[i * CHUNK:(i + 1) * CHUNK])
        await finish_up(c, sa, len(a))
        await finish_up(c, sb, len(b))
        await wait_done(c, {sa, sb})
    finally:
        await c.close()
    for name, payload in (("a.bin", a), ("b.bin", b)):
        got = open(os.path.join(data, "users", user, name), "rb").read()
        assert got == payload, name


@pytest.mark.asyncio
async def test_two_connections_upload_at_once(server):
    """同一账号两条连接同时上传，两份文件都完整。"""
    base, data = server
    user = "race-" + secrets.token_hex(3)
    key, jwk = make_identity()
    register(base, user, jwk)
    one, two = os.urandom(2 * CHUNK), os.urandom(2 * CHUNK)
    await asyncio.gather(
        upload_one(base, user, "one.bin", one, key, jwk),
        upload_one(base, user, "two.bin", two, key, jwk),
    )
    for name, payload in (("one.bin", one), ("two.bin", two)):
        got = open(os.path.join(data, "users", user, name), "rb").read()
        assert got == payload, name
        assert hashlib.sha256(got).digest() == hashlib.sha256(payload).digest()
