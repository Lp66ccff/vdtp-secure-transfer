"""帧解码的模糊测试：随机字节进来，只许抛 FrameError 或返回空列表。"""

from __future__ import annotations

import random

from app import frame as P


def test_random_bytes_only_raise_frame_error():
    rnd = random.Random(20261122)
    for _ in range(400):
        data = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 96)))
        dec = P.FrameDecoder()
        try:
            frames = dec.feed(data)
        except P.FrameError:
            continue
        assert isinstance(frames, list)


def test_valid_header_with_random_payload():
    rnd = random.Random(7)
    dec = P.FrameDecoder()
    for _ in range(50):
        payload = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 4096)))
        raw = P.pack(P.T_DATA, payload, stream=rnd.randint(0, 8), seq=rnd.randint(0, 1 << 20))
        frames = dec.feed(raw)
        assert len(frames) == 1
        assert frames[0].payload == payload


def test_truncated_stream_never_loses_bytes():
    dec = P.FrameDecoder()
    raw = P.pack(P.T_DATA, b"x" * 1000)
    for i in range(0, len(raw), 7):
        frames = dec.feed(raw[i:i + 7])
        assert frames == [] or frames[0].payload == b"x" * 1000
