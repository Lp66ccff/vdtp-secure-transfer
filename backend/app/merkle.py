"""Merkle 块树：块哈希、上一层节点、根。

叶子：SHA-256(0x00 ‖ 块)；内部节点：SHA-256(0x01 ‖ 左 ‖ 右)。
奇数个叶子时复制最后一个补齐，树形只由块数决定。
"""

from __future__ import annotations

import hashlib

EMPTY_ROOT = b"\x00" * 32


def leaf(chunk: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + chunk).digest()


def node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_of(leaves: list[bytes]) -> bytes:
    if not leaves:
        return EMPTY_ROOT
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]
