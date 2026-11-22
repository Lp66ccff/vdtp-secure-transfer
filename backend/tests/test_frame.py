"""帧编解码的单元测试。"""

from __future__ import annotations

import pytest

from app import frame as P


def test_roundtrip():
    dec = P.FrameDecoder()
    raw = P.pack(P.T_HELLO, P.control({"ver": 1, "user": "a"}))
    frames = dec.feed(raw)
    assert len(frames) == 1
    assert frames[0].type == P.T_HELLO
    assert P.parse_control(frames[0].payload) == {"ver": 1, "user": "a"}


def test_header_is_16_bytes():
    assert P.HDR_SIZE == 16
    assert len(P.pack(P.T_PING)) == 16


def test_fragmented_feed():
    dec = P.FrameDecoder()
    raw = P.pack(P.T_PING)
    assert dec.feed(raw[:5]) == []
    assert dec.feed(raw[5:15]) == []
    frames = dec.feed(raw[15:])
    assert [f.type for f in frames] == [P.T_PING]


def test_two_frames_in_one_chunk():
    dec = P.FrameDecoder()
    raw = P.pack(P.T_PING) + P.pack(P.T_PONG)
    assert [f.type for f in dec.feed(raw)] == [P.T_PING, P.T_PONG]


def test_bad_magic():
    dec = P.FrameDecoder()
    raw = bytearray(P.pack(P.T_PING))
    raw[0] = 0x00
    with pytest.raises(P.FrameError) as exc:
        dec.feed(bytes(raw))
    assert exc.value.code == "BAD_FRAME"


def test_bad_version():
    raw = bytearray(P.pack(P.T_PING))
    raw[2] = 9
    with pytest.raises(P.FrameError):
        P.FrameDecoder().feed(bytes(raw))


def test_oversize_length_rejected_before_payload():
    raw = bytearray(P.pack(P.T_PING))
    raw[12:16] = (P.MAX_PAYLOAD + 1).to_bytes(4, "big")
    with pytest.raises(P.FrameError):
        P.FrameDecoder().feed(bytes(raw))


def test_control_is_sorted_and_compact():
    payload = P.control({"b": 1, "a": 2})
    assert payload == b'{"a":2,"b":1}'


def test_control_rejects_non_object():
    with pytest.raises(P.FrameError):
        P.parse_control(b'[1,2,3]')


def test_data_prefix():
    payload = P.data(1024, b"abc")
    assert payload[:8] == (1024).to_bytes(8, "big")
    assert payload[8:] == b"abc"
