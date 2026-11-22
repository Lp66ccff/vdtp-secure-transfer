"""续传与限速的冒烟：传一半掐线，重连后凭票据接着传。

    python3 tools/resume_smoke.py [http://127.0.0.1:8000]
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
SIZE = 4 << 20


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


def register(base: str, user: str, jwk: dict) -> dict:
    body = json.dumps({"user": user, "pub": jwk}).encode()
    req = urllib.request.Request(base + "/api/register", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())


async def recv_frame(ws, dec: P.FrameDecoder) -> P.Frame:
    while True:
        frames = dec.feed(await asyncio.wait_for(ws.recv(), timeout=15))
        if frames:
            return frames[0]


async def wait_type(ws, dec, ftype, stream=None, skip=(P.T_ACK,)):
    while True:
        fr = await recv_frame(ws, dec)
        if fr.type in skip:
            continue
        if fr.type == ftype and (stream is None or fr.stream == stream):
            return fr
        if fr.type == P.T_ERROR:
            raise SystemExit(f"服务端报错：{P.parse_control(fr.payload)}")


async def handshake(ws, dec, user, key, jwk, seq):
    await ws.send(P.pack(P.T_HELLO, P.control({"ver": P.VER, "user": user}), seq=seq()))
    ack = P.parse_control((await recv_frame(ws, dec)).payload)
    challenge = P.parse_control((await recv_frame(ws, dec)).payload)
    nonce = bytes.fromhex(challenge["nonce"])
    await ws.send(P.pack(P.T_AUTH_RESPONSE, P.control({
        "pub": jwk, "sig": auth.b64u(sign_raw(key, nonce + ack["sid"].encode()))}), seq=seq()))
    return P.parse_control((await recv_frame(ws, dec)).payload)


async def main(base: str) -> int:
    from websockets.asyncio.client import connect

    key, jwk = make_identity()
    user = "resume-" + secrets.token_hex(3)
    register(base, user, jwk)
    payload = os.urandom(SIZE)
    chunks = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)]
    root = merkle.root_of([merkle.leaf(c) for c in chunks])
    digest = hashlib.sha256(payload).hexdigest()
    ws_url = base.replace("http://", "ws://") + "/ws"
    print(f"用户 {user}，准备传 {SIZE >> 20} MiB，{len(chunks)} 块")

    seq = [0]

    def bump():
        seq[0] += 1
        return seq[0]

    # ---------------------------------------------------------- 第一段：传 1 MiB 后掐线
    async with connect(ws_url, max_size=2 << 20) as ws:
        dec = P.FrameDecoder()
        ok = await handshake(ws, dec, user, key, jwk, bump)
        ticket = ok["ticket"]
        print(f"认证通过，档位 {ok['rate'] >> 20} MiB/s")
        await ws.send(P.pack(P.T_OPEN, P.control({
            "path": "续传.bin", "mode": "up", "size": SIZE, "root": root.hex()}), seq=bump()))
        opened = P.parse_control((await recv_frame(ws, dec)).payload)
        stream = opened["stream"]
        t0 = time.perf_counter()
        for i in range(4):
            await ws.send(P.pack(P.T_DATA, P.data(i * CHUNK, chunks[i]), stream=stream,
                                 seq=bump()))
        await asyncio.sleep(0.3)
        print(f"已发 4 块后主动断开（{1000*(time.perf_counter()-t0):.0f} ms）")

    await asyncio.sleep(0.6)

    # ---------------------------------------------------------- 第二段：重连续传
    async with connect(ws_url, max_size=2 << 20) as ws:
        dec = P.FrameDecoder()
        ok = await handshake(ws, dec, user, key, jwk, bump)
        await ws.send(P.pack(P.T_RESUME, P.control({"ticket": ticket}), seq=bump()))
        resumed = P.parse_control((await recv_frame(ws, dec)).payload)
        streams = resumed.get("streams", [])
        if not streams:
            raise SystemExit("没有可续传的流")
        st = streams[0]
        offset = st["offset"]
        print(f"RESUME_OK 恢复 stream={st['stream']} offset={offset}")
        assert offset == 4 * CHUNK, offset

        t1 = time.perf_counter()
        index = offset // CHUNK
        for i in range(index, len(chunks)):
            await ws.send(P.pack(P.T_DATA, P.data(i * CHUNK, chunks[i]), stream=st["stream"],
                                 seq=bump()))
        await ws.send(P.pack(P.T_DONE, P.control({"size": SIZE, "sha256": digest}),
                             stream=st["stream"], seq=bump()))
        await wait_type(ws, dec, P.T_DONE_OK, st["stream"])
        elapsed = time.perf_counter() - t1
        moved = SIZE - offset
        print(f"续传 {moved >> 20} MiB 用时 {elapsed:.2f}s，约 {moved/elapsed/2**20:.2f} MiB/s")

    path = os.path.join("data", "users", user, "续传.bin")
    got = hashlib.sha256(open(path, "rb").read()).hexdigest() if os.path.exists(path) else ""
    print(f"盘上文件 {os.path.getsize(path) if got else 0} 字节，摘要{'一致' if got == digest else '不符'}")
    assert got == digest
    print("ok")
    return 0


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
    raise SystemExit(asyncio.run(main(base)))
