"""令牌桶：按用户档位限速，超速的调用方在 take() 里等。"""

from __future__ import annotations

import asyncio
import time


class TokenBucket:
    def __init__(self, rate: float, burst: float | None = None):
        self.rate = float(rate)
        self.capacity = float(burst if burst is not None else max(rate, 64 << 10))
        self.tokens = self.capacity
        self.stamp = time.monotonic()
        self.lock = asyncio.Lock()

    async def take(self, amount: int) -> None:
        if self.rate <= 0:
            return
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.stamp) * self.rate)
                self.stamp = now
                if self.tokens >= amount:
                    self.tokens -= amount
                    return
                await asyncio.sleep((amount - self.tokens) / self.rate)
