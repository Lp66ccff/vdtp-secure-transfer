"""VDTP/2 帧编解码：16 字节定长头加载荷。

头布局见 docs/协议.md：

    magic(2) ver(1) type(1) flags(1) rsv(1) stream(2) seq(4) length(4)

大端。DATA 的载荷是 ``offset:u64 || 块``，其余消息是紧凑 JSON。
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass

MAGIC = 0x5654
VER = 1
HDR = struct.Struct(">HBBBBHII")
HDR_SIZE = HDR.size
MAX_PAYLOAD = 1 << 20
MAX_CONTROL = 64 << 10
DATA_PREFIX = struct.Struct(">Q")

# ---------------------------------------------------------------- 消息类型
T_HELLO = 1
T_HELLO_ACK = 2
T_AUTH_CHALLENGE = 3
T_AUTH_RESPONSE = 4
T_AUTH_OK = 5
T_LIST = 6
T_LIST_OK = 7
T_OPEN = 8
T_OPEN_OK = 9
T_DATA = 10
T_ACK = 11
T_DONE = 12
T_DONE_OK = 13
T_RESUME = 14
T_RESUME_OK = 15
T_PING = 16
T_PONG = 17
T_ERROR = 18
T_BYE = 19

NAMES = {
    T_HELLO: "HELLO", T_HELLO_ACK: "HELLO_ACK",
    T_AUTH_CHALLENGE: "AUTH_CHALLENGE", T_AUTH_RESPONSE: "AUTH_RESPONSE",
    T_AUTH_OK: "AUTH_OK", T_LIST: "LIST", T_LIST_OK: "LIST_OK",
    T_OPEN: "OPEN", T_OPEN_OK: "OPEN_OK", T_DATA: "DATA", T_ACK: "ACK",
    T_DONE: "DONE", T_DONE_OK: "DONE_OK", T_RESUME: "RESUME",
    T_RESUME_OK: "RESUME_OK", T_PING: "PING", T_PONG: "PONG",
    T_ERROR: "ERROR", T_BYE: "BYE",
}

FLAG_LAST = 0x01


class FrameError(Exception):
    """帧不合法：magic、ver 或 length 对不上。"""

    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code


@dataclass(frozen=True)
class Frame:
    type: int
    stream: int
    seq: int
    payload: bytes

    @property
    def name(self) -> str:
        return NAMES.get(self.type, f"UNKNOWN({self.type})")


def pack(ftype: int, payload: bytes = b"", *, stream: int = 0, seq: int = 0,
         flags: int = 0) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise FrameError("BAD_FRAME", f"载荷 {len(payload)} 超过 {MAX_PAYLOAD}")
    header = HDR.pack(MAGIC, VER, ftype, flags, 0, stream, seq, len(payload))
    return header + payload


def control(obj: dict) -> bytes:
    """控制消息的载荷：键排序、无空格的 JSON。"""
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_CONTROL:
        raise FrameError("BAD_FRAME", "控制载荷超限")
    return raw


def data(offset: int, chunk: bytes) -> bytes:
    return DATA_PREFIX.pack(offset) + chunk


def parse_control(payload: bytes) -> dict:
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrameError("BAD_FRAME", f"载荷不是合法 JSON：{exc}") from exc
    if not isinstance(obj, dict):
        raise FrameError("BAD_FRAME", "控制载荷必须是 JSON 对象")
    return obj


class FrameDecoder:
    """流式解码：喂字节，出完整帧。半个帧先留在缓冲里。"""

    def __init__(self, max_payload: int = MAX_PAYLOAD):
        self.buf = bytearray()
        self.max_payload = max_payload
        self.bytes_seen = 0
        self.frames_in = 0

    def feed(self, data: bytes) -> list[Frame]:
        self.buf.extend(data)
        self.bytes_seen += len(data)
        out: list[Frame] = []
        while len(self.buf) >= HDR_SIZE:
            magic, ver, ftype, flags, _rsv, stream, seq, length = HDR.unpack_from(self.buf)
            if magic != MAGIC:
                raise FrameError("BAD_FRAME", f"magic 0x{magic:04x} 不对")
            if ver != VER:
                raise FrameError("BAD_FRAME", f"版本 {ver} 不支持")
            if length > self.max_payload:
                raise FrameError("BAD_FRAME", f"长度 {length} 超过上限")
            if len(self.buf) < HDR_SIZE + length:
                break
            payload = bytes(self.buf[HDR_SIZE:HDR_SIZE + length])
            del self.buf[:HDR_SIZE + length]
            out.append(Frame(ftype, stream, seq, payload))
            self.frames_in += 1
        return out
