"""VDTP/2 网关：WebSocket 端点，目前只实现握手、心跳与错误。

骨架阶段能跑通这一段：一个连接、一次 HELLO、之后 PING/PONG。
认证、目录、传输在里程碑 2 与 3 加。
"""

from __future__ import annotations

import asyncio
import os
import secrets
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from . import frame as P

HANDSHAKE_TIMEOUT = 5.0
HEARTBEAT_TIMEOUT = 120.0

app = FastAPI(title="VDTP/2 gateway", version="0.1.0")


@app.get("/api/health")
async def health() -> dict:
    return {"ok": True, "proto": "VDTP/2", "ver": P.VER}


class Session:
    """一条连接上的协议状态。"""

    def __init__(self, ws: WebSocket):
        self.ws = ws
        self.sid = secrets.token_hex(8)
        self.nonce = secrets.token_bytes(32)
        self.hello = False
        self.authed = False
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
            timeout = HANDSHAKE_TIMEOUT if not sess.hello else HEARTBEAT_TIMEOUT
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
                if not sess.hello and fr.type != P.T_HELLO:
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
    if fr.type == P.T_HELLO:
        body = P.parse_control(fr.payload)
        if int(body.get("ver", 0)) != P.VER:
            await sess.error("BAD_FRAME", f"版本 {body.get('ver')} 不支持")
            return
        sess.hello = True
        await sess.send_json(P.T_HELLO_ACK, {
            "ver": P.VER,
            "sid": sess.sid,
            "nonce": sess.nonce.hex(),
            "user": body.get("user", ""),
        })
        return

    if fr.type == P.T_PING:
        await sess.send(P.T_PONG)
        return

    if fr.type == P.T_BYE:
        raise WebSocketDisconnect(code=1000)

    await sess.error("NOT_IMPLEMENTED", f"{fr.name} 还没实现", stream=fr.stream)


def main() -> None:  # pragma: no cover - 入口给 uvicorn 用
    import uvicorn

    host = os.environ.get("VDTP_HOST", "127.0.0.1")
    port = int(os.environ.get("VDTP_PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":  # pragma: no cover
    main()
