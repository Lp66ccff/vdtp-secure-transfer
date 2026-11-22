"""握手与心跳的冒烟测试：连真起的服务端，说一遍 HELLO 与 PING。

    python3 tools/smoke.py [ws://127.0.0.1:8000/ws]
"""

from __future__ import annotations

import asyncio
import sys
import time

sys.path.insert(0, ".")

from app import frame as P  # noqa: E402


async def main(url: str) -> int:
    from websockets.asyncio.client import connect

    async with connect(url) as ws:
        t0 = time.perf_counter()
        await ws.send(P.pack(P.T_HELLO, P.control({"ver": P.VER, "user": "smoke",
                                                   "caps": ["ping"]}), seq=1))
        raw = await asyncio.wait_for(ws.recv(), timeout=5)
        fr = P.FrameDecoder().feed(raw)[0]
        assert fr.type == P.T_HELLO_ACK, fr.name
        ack = P.parse_control(fr.payload)
        print(f"HELLO_ACK sid={ack['sid']} nonce={len(ack['nonce'])//2} 字节 "
              f"{1000*(time.perf_counter()-t0):.1f} ms")

        for i in range(3):
            t = time.perf_counter()
            await ws.send(P.pack(P.T_PING, seq=2 + i))
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            fr = P.FrameDecoder().feed(raw)[0]
            assert fr.type == P.T_PONG, fr.name
            print(f"PONG seq={fr.seq} {1000*(time.perf_counter()-t):.2f} ms")

        await ws.send(P.pack(P.T_BYE, P.control({"reason": "smoke"}), seq=9))
    print("ok")
    return 0


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8000/ws"
    raise SystemExit(asyncio.run(main(url)))
