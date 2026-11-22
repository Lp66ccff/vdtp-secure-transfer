"""令牌桶的时序与并发测试。"""

from __future__ import annotations

import asyncio
import time

import pytest

from app.bucket import TokenBucket

pytestmark = pytest.mark.asyncio


async def test_rate_is_respected():
    bucket = TokenBucket(rate=512 << 10, burst=64 << 10)   # 512 KiB/s
    start = time.monotonic()
    for _ in range(8):
        await bucket.take(64 << 10)
    elapsed = time.monotonic() - start
    # 8 × 64 KiB = 512 KiB，扣掉 64 KiB 的突发，应当约 0.9 秒
    assert 0.6 <= elapsed <= 2.0, elapsed


async def test_two_takers_share_one_bucket():
    bucket = TokenBucket(rate=512 << 10, burst=64 << 10)
    got = []

    async def worker(tag):
        for _ in range(4):
            await bucket.take(64 << 10)
            got.append(tag)

    start = time.monotonic()
    await asyncio.gather(worker("a"), worker("b"))
    elapsed = time.monotonic() - start
    assert got.count("a") == 4 and got.count("b") == 4
    assert 0.4 <= elapsed <= 2.5, elapsed


async def test_zero_rate_does_not_block():
    bucket = TokenBucket(rate=0)
    start = time.monotonic()
    await bucket.take(10 << 20)
    assert time.monotonic() - start < 0.2
