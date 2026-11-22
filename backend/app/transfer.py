"""块文件传输：上传落盘、下载推流、块校验与收尾。

上传先落 .part 临时文件，DONE 时比对大小、全文 SHA-256 与 Merkle 根，全对才改名。
下载由一条后台任务按窗口推 DATA，客户端回 ACK 才继续。
"""

from __future__ import annotations

import asyncio
import hashlib
import os

from . import frame as P
from . import merkle

CHUNK = 256 << 10
ACK_EVERY = 4 << 20
WINDOW = 4 << 20
MAX_FILE = 8 << 30


class TransferError(Exception):
    def __init__(self, code: str, msg: str):
        super().__init__(msg)
        self.code = code
        self.msg = msg


class Upload:
    def __init__(self, stream: int, rel: str, final: str, temp: str,
                 size: int, root: bytes):
        self.id = stream
        self.rel = rel
        self.final = final
        self.temp = temp
        self.size = size
        self.root = root
        self.offset = 0
        self.last_ack = 0
        self.digest = hashlib.sha256()
        self.leaves: list[bytes] = []
        self.fh = open(temp, "wb")

    def write(self, offset: int, chunk: bytes) -> None:
        if offset != self.offset:
            raise TransferError("BAD_STREAM", f"偏移对不上：期望 {self.offset}，收到 {offset}")
        if offset + len(chunk) > self.size:
            raise TransferError("BAD_FRAME", "写超了声明的大小")
        self.fh.write(chunk)
        self.digest.update(chunk)
        self.leaves.append(merkle.leaf(chunk))
        self.offset += len(chunk)

    def finish(self, size: int, sha256: str) -> None:
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.fh.close()
        if size != self.size or self.offset != self.size:
            raise TransferError("BAD_FRAME", f"大小不符：声明 {self.size}，收到 {self.offset}")
        if self.digest.hexdigest() != sha256:
            raise TransferError("HASH_MISMATCH", "全文 SHA-256 不符")
        if merkle.root_of(self.leaves) != self.root:
            raise TransferError("HASH_MISMATCH", "Merkle 根不符")
        os.makedirs(os.path.dirname(self.final), exist_ok=True)
        os.replace(self.temp, self.final)

    def abort(self) -> None:
        try:
            self.fh.close()
        except Exception:
            pass
        try:
            os.unlink(self.temp)
        except OSError:
            pass


class Download:
    def __init__(self, stream: int, rel: str, path: str, size: int):
        self.id = stream
        self.rel = rel
        self.path = path
        self.size = size
        self.offset = 0
        self.acked = 0
        self.ack_event = asyncio.Event()
        self.task: asyncio.Task | None = None

    def ack(self, offset: int) -> None:
        self.acked = max(self.acked, offset)
        self.ack_event.set()


async def pump(sess, st: Download) -> None:
    """读一块发一块，窗口满了就等 ACK。"""
    digest = hashlib.sha256()
    try:
        with open(st.path, "rb") as fh:
            while st.offset < st.size:
                if st.offset - st.acked >= WINDOW:
                    st.ack_event.clear()
                    await st.ack_event.wait()
                chunk = fh.read(min(CHUNK, st.size - st.offset))
                if not chunk:
                    break
                await sess.send(P.T_DATA, P.data(st.offset, chunk), stream=st.id)
                digest.update(chunk)
                st.offset += len(chunk)
        await sess.send_json(P.T_DONE, {"size": st.size, "sha256": digest.hexdigest()},
                             stream=st.id)
    except (asyncio.CancelledError, RuntimeError, ConnectionError):
        pass
