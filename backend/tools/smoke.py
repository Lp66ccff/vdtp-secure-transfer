"""整趟冒烟：注册、握手、挑战签名、认证、列目录、上传、下载、越权、心跳。

    python3 tools/smoke.py [http://127.0.0.1:8000]
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.request

sys.path.insert(0, ".")

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

from app import auth, frame as P  # noqa: E402
from app import merkle  # noqa: E402

CHUNK = 256 << 10


def make_identity():
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "EC", "crv": "P-256",
        "x": auth.b64u(nums.x.to_bytes(32, "big")),
        "y": auth.b64u(nums.y.to_bytes(32, "big")),
    }
    return key, jwk


def sign_raw(key, message: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def register(base: str, user: str, jwk: dict) -> dict:
    body = json.dumps({"user": user, "pub": jwk}).encode()
    req = urllib.request.Request(base + "/api/register", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


async def recv_frame(ws, dec: P.FrameDecoder) -> P.Frame:
    while True:
        frames = dec.feed(await asyncio.wait_for(ws.recv(), timeout=5))
        if frames:
            return frames[0]


async def main(base: str) -> int:
    from websockets.asyncio.client import connect

    key, jwk = make_identity()
    user = "smoke-" + secrets.token_hex(3)
    info = register(base, user, jwk)
    print(f"register {user} created={info['created']} thumb={info['thumbprint'][:12]}…")

    ws_url = base.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
    dec = P.FrameDecoder()
    seq = 0

    def bump() -> int:
        nonlocal seq
        seq += 1
        return seq

    async with connect(ws_url, max_size=2 << 20) as ws:
        t0 = time.perf_counter()
        await ws.send(P.pack(P.T_HELLO, P.control({"ver": P.VER, "user": user,
                                                   "caps": ["ping", "list", "xfer"]}),
                             seq=bump()))
        ack = P.parse_control((await recv_frame(ws, dec)).payload)
        print(f"HELLO_ACK sid={ack['sid']} {1000*(time.perf_counter()-t0):.1f} ms")

        challenge = P.parse_control((await recv_frame(ws, dec)).payload)
        nonce = bytes.fromhex(challenge["nonce"])
        print(f"AUTH_CHALLENGE nonce={len(nonce)} 字节")

        message = nonce + ack["sid"].encode()
        await ws.send(P.pack(P.T_AUTH_RESPONSE, P.control({
            "pub": jwk, "sig": auth.b64u(sign_raw(key, message))}), seq=bump()))
        auth_ok = P.parse_control((await recv_frame(ws, dec)).payload)
        print(f"AUTH_OK user={auth_ok['user']} rate={auth_ok['rate']} 票据={len(auth_ok['ticket'])}B")

        await ws.send(P.pack(P.T_LIST, P.control({"path": ""}), seq=bump()))
        listing = P.parse_control((await recv_frame(ws, dec)).payload)
        print(f"LIST_OK 根目录 {len(listing['entries'])} 项")

        # ---------------------------------------------------------- 上传
        payload = os.urandom(1 << 20)
        chunks = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)]
        root = merkle.root_of([merkle.leaf(c) for c in chunks])
        t = time.perf_counter()
        await ws.send(P.pack(P.T_OPEN, P.control({
            "path": "smoke.bin", "mode": "up", "size": len(payload),
            "root": root.hex()}), seq=bump()))
        fr = await recv_frame(ws, dec)
        opened = P.parse_control(fr.payload)
        assert fr.stream == opened["stream"], (fr.stream, opened["stream"])
        stream = opened["stream"]
        for i, chunk in enumerate(chunks):
            await ws.send(P.pack(P.T_DATA, P.data(i * CHUNK, chunk), stream=stream,
                                 seq=bump()))
        await ws.send(P.pack(P.T_DONE, P.control({
            "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}),
            stream=stream, seq=bump()))
        done = await recv_frame(ws, dec)
        assert done.type == P.T_DONE_OK and done.stream == stream, (done.name, done.stream)
        print(f"上传 {len(payload)} 字节 {stream=} "
              f"{1000*(time.perf_counter()-t):.0f} ms")

        # ---------------------------------------------------------- 下载
        t = time.perf_counter()
        await ws.send(P.pack(P.T_OPEN, P.control({"path": "smoke.bin", "mode": "down"}),
                             seq=bump()))
        fr = await recv_frame(ws, dec)
        opened = P.parse_control(fr.payload)
        assert fr.stream == opened["stream"], (fr.stream, opened["stream"])
        stream = opened["stream"]
        got = bytearray()
        while True:
            fr = await recv_frame(ws, dec)
            if fr.type == P.T_DATA:
                offset = int.from_bytes(fr.payload[:8], "big")
                got[offset:offset + len(fr.payload) - 8] = fr.payload[8:]
                await ws.send(P.pack(P.T_ACK, P.control({"offset": offset + len(fr.payload) - 8}),
                                     stream=fr.stream, seq=bump()))
            elif fr.type == P.T_DONE:
                body = P.parse_control(fr.payload)
                await ws.send(P.pack(P.T_DONE_OK, P.control({"stream": fr.stream}),
                                     stream=fr.stream, seq=bump()))
                break
            elif fr.type == P.T_ERROR:
                raise SystemExit(f"下载失败：{P.parse_control(fr.payload)}")
        same = bytes(got) == payload and hashlib.sha256(got).hexdigest() == body["sha256"]
        print(f"下载 {len(got)} 字节 {1000*(time.perf_counter()-t):.0f} ms 校验{'通过' if same else '不符'}")
        assert same

        # ---------------------------------------------------------- 越权与心跳
        await ws.send(P.pack(P.T_LIST, P.control({"path": "../../etc"}), seq=bump()))
        err = P.parse_control((await recv_frame(ws, dec)).payload)
        print(f"越权请求被拒：{err['code']} {err['msg']}")

        t = time.perf_counter()
        await ws.send(P.pack(P.T_PING, seq=bump()))
        await recv_frame(ws, dec)
        print(f"PONG {1000*(time.perf_counter()-t):.2f} ms")

        await ws.send(P.pack(P.T_BYE, P.control({"reason": "smoke"}), seq=bump()))
    print("ok")
    return 0


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    raise SystemExit(asyncio.run(main(base)))
