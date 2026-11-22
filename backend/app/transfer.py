"""块文件传输：上传落盘、下载推流、块校验、续传与限速。

上传先落 .part 临时文件，DONE 时比对大小、全文 SHA-256 与 Merkle 根，全对才改名。
断线后 .part 留着，续传时按文件内容重建摘要与叶子，偏移从文件大小接着走。
下载由一条后台任务按窗口推 DATA，客户端回 ACK 才继续；令牌桶在发送前扣额度。
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
                 size: int, root: bytes, *, resume: bool = False):
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
        if resume:
            self._rebuild()
        self.fh = open(temp, "ab" if resume else "wb")

    def _rebuild(self) -> None:
        """按盘上的 .part 重建偏移、摘要与叶子，断线前写的部分接着算。"""
        with open(self.temp, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                self.digest.update(chunk)
                self.leaves.append(merkle.leaf(chunk))
        self.offset = os.path.getsize(self.temp)
        self.last_ack = self.offset

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

    def park(self) -> dict:
        """断线时把续传需要的东西留下来。"""
        try:
            self.fh.flush()
            self.fh.close()
        except Exception:
            pass
        return {"kind": "up", "stream": self.id, "rel": self.rel, "temp": self.temp,
                "final": self.final, "size": self.size, "root": self.root.hex(),
                "offset": self.offset}

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
    def __init__(self, stream: int, rel: str, path: str, size: int, offset: int = 0):
        self.id = stream
        self.rel = rel
        self.path = path
        self.size = size
        self.offset = max(0, min(offset, size))
        self.acked = self.offset
        self.ack_event = asyncio.Event()
        self.task: asyncio.Task | None = None

    def ack(self, offset: int) -> None:
        self.acked = max(self.acked, offset)
        self.ack_event.set()


async def pump(sess, st: Download, bucket=None) -> None:
    """读一块发一块，窗口满了就等 ACK；有桶先扣额度。"""
    digest = None
    try:
        if st.offset == 0:
            digest = hashlib.sha256()
        with open(st.path, "rb") as fh:
            fh.seek(st.offset)
            while st.offset < st.size:
                if st.offset - st.acked >= WINDOW:
                    st.ack_event.clear()
                    await st.ack_event.wait()
                chunk = fh.read(min(CHUNK, st.size - st.offset))
                if not chunk:
                    break
                if bucket is not None:
                    await bucket.take(len(chunk))
                await sess.send(P.T_DATA, P.data(st.offset, chunk), stream=st.id)
                if digest is not None:
                    digest.update(chunk)
                st.offset += len(chunk)
        if digest is None:
            digest = hashlib.sha256()
            with open(st.path, "rb") as fh:
                for block in iter(lambda: fh.read(CHUNK), b""):
                    digest.update(block)
        await sess.send_json(P.T_DONE, {"size": st.size, "sha256": digest.hexdigest()},
                             stream=st.id)
    except (asyncio.CancelledError, RuntimeError, ConnectionError):
        pass
