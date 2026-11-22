"""量一档的实际上传速率，给报告的实验数据用。

    python3 tools/bench_rate.py [MiB] [free|vip]

每次建一个新用户，传完打印 MiB/s。档位在认证时生效，所以要建完再认证。
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
from app.store import Store  # noqa: E402

CHUNK = 256 << 10


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


async def recv(ws, dec) -> P.Frame:
    while True:
        frames = dec.feed(await asyncio.wait_for(ws.recv(), timeout=30))
        if frames:
            return frames[0]


async def main(base: str, mib: int, tier: str) -> int:
    from websockets.asyncio.client import connect

    key, jwk = make_identity()
    user = f"bench-{tier}-" + secrets.token_hex(3)
    register(base, user, jwk)
    Store(os.environ.get("VDTP_DATA", "data")).set_tier(user, tier)

    payload = os.urandom(mib << 20)
    chunks = [payload[i:i + CHUNK] for i in range(0, len(payload), CHUNK)]
    root = merkle.root_of([merkle.leaf(c) for c in chunks])
    digest = hashlib.sha256(payload).hexdigest()

    async with connect(base.replace("http://", "ws://") + "/ws", max_size=2 << 20) as ws:
        dec = P.FrameDecoder()
        seq = 0

        def bump():
            nonlocal seq
            seq += 1
            return seq

        await ws.send(P.pack(P.T_HELLO, P.control({"ver": P.VER, "user": user}), seq=bump()))
        ack = P.parse_control((await recv(ws, dec)).payload)
        challenge = P.parse_control((await recv(ws, dec)).payload)
        nonce = bytes.fromhex(challenge["nonce"])
        await ws.send(P.pack(P.T_AUTH_RESPONSE, P.control({
            "pub": jwk, "sig": auth.b64u(sign_raw(key, nonce + ack["sid"].encode()))}), seq=bump()))
        ok = P.parse_control((await recv(ws, dec)).payload)

        await ws.send(P.pack(P.T_OPEN, P.control({
            "path": "bench.bin", "mode": "up", "size": len(payload), "root": root.hex()}),
            seq=bump()))
        opened = P.parse_control((await recv(ws, dec)).payload)
        stream = opened["stream"]

        t0 = time.perf_counter()
        for i, chunk in enumerate(chunks):
            await ws.send(P.pack(P.T_DATA, P.data(i * CHUNK, chunk), stream=stream, seq=bump()))
        await ws.send(P.pack(P.T_DONE, P.control({"size": len(payload), "sha256": digest}),
                             stream=stream, seq=bump()))
        while True:
            fr = await recv(ws, dec)
            if fr.type == P.T_DONE_OK:
                break
            if fr.type == P.T_ERROR:
                raise SystemExit(f"失败：{P.parse_control(fr.payload)}")
        elapsed = time.perf_counter() - t0

    rate = mib / elapsed
    print(f"{tier:4s} 档位声明 {ok['rate']/2**20:.0f} MiB/s，实传 {mib} MiB 用 {elapsed:.2f}s，"
          f"约 {rate:.2f} MiB/s")
    return 0


if __name__ == "__main__":
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    tier = sys.argv[2] if len(sys.argv) > 2 else "free"
    base = sys.argv[3] if len(sys.argv) > 3 else "http://127.0.0.1:8000"
    raise SystemExit(asyncio.run(main(base, size, tier)))
