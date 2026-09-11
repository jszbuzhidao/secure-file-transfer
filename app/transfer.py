"""传输调度层：分块流式收发 + 断点续传。

这一层把「加密层」和「协议层」拼起来，对外只暴露两个函数：

    send_file(...)     发送端：从 offset 开始，一块块加密发出去
    receive_file(...)  接收端：一块块收下来解密落盘，支持中途断开后续传

对比原版的三处行为差异：

1. **内存**：原版 ``f.read()`` 把整个文件读进内存再加密，1 GB 文件就需要 ~2 GB 内存
   （明文 + 密文同时驻留）。现在固定 64 KiB 滑动窗口，内存占用恒定。
2. **续传**：原版断线即从头再来。现在接收端记录已落盘块，重连后只传缺失部分。
3. **完整性**：原版整文件一次性校验。现在每块有 GCM 认证标签（及时发现问题），
   收完再做整文件 SHA-256 二次确认。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

from . import config, crypto, protocol
from .protocol import MessageType, ProtocolError
from .resume_store import ResumeStore

ProgressFn = Optional[Callable[[int, int], None]]


class TransferError(Exception):
    """传输层错误。"""


# ---------------------------------------------------------------------------
# 文件元信息
# ---------------------------------------------------------------------------


@dataclass
class FileInfo:
    """文件描述。``file_id`` 用内容 SHA-256 做内容寻址，天然幂等。"""

    file_id: str
    name: str
    size: int
    sha256: str
    chunk_size: int

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id,
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "chunk_size": self.chunk_size,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FileInfo":
        return cls(
            file_id=data["file_id"],
            name=os.path.basename(data["name"]),
            size=int(data["size"]),
            sha256=data["sha256"],
            chunk_size=int(data.get("chunk_size", config.CHUNK_SIZE)),
        )


def inspect_file(path, chunk_size: int = config.CHUNK_SIZE) -> FileInfo:
    """扫描文件，算出大小与 SHA-256，构造 ``FileInfo``。"""
    path = os.fspath(path)
    size = os.path.getsize(path)
    digest = crypto.sha256_file(path, chunk_size)
    return FileInfo(
        file_id=digest,
        name=os.path.basename(path),
        size=size,
        sha256=digest,
        chunk_size=chunk_size,
    )


def iter_file_chunks(
    path, chunk_size: int = config.CHUNK_SIZE, start: int = 0
) -> Iterator[tuple[int, bytes]]:
    """按块迭代文件，产出 ``(offset, 明文块)``。``start`` 用于续传定位。"""
    with open(path, "rb") as fh:
        if start:
            fh.seek(start)
        offset = start
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            yield offset, block
            offset += len(block)


def _emit(progress: ProgressFn, done: int, total: int) -> None:
    if progress is not None:
        progress(done, total)


# ---------------------------------------------------------------------------
# 发送端
# ---------------------------------------------------------------------------


def send_file(
    sock,
    enc_key: bytes,
    path,
    info: FileInfo,
    start_offset: int = 0,
    progress: ProgressFn = None,
    seq_start: int = 0,
) -> int:
    """把文件从 ``start_offset`` 起分块加密发送。

    调用前提：上层已完成 ``PUT_BEGIN`` / ``PUT_RESUME`` 协商，双方对
    ``start_offset`` 达成一致。发送完不负责发结束帧，由调用方决定发
    ``PUT_END`` 还是 ``GET_END``（上传/下载语义不同）。
    """
    sent = 0
    seq = seq_start
    total = info.size - start_offset
    for offset, block in iter_file_chunks(path, info.chunk_size, start_offset):
        aad = crypto.chunk_aad(info.file_id, offset)
        ciphertext = crypto.aes_gcm_encrypt(enc_key, block, aad)
        payload = protocol.pack_data_payload(offset, ciphertext)
        protocol.send_frame(sock, MessageType.DATA, payload, seq=seq)
        seq += 1
        sent += len(block)
        _emit(progress, sent, total)
    return sent


# ---------------------------------------------------------------------------
# 接收端
# ---------------------------------------------------------------------------


def receive_file(
    sock,
    enc_key: bytes,
    store: ResumeStore,
    end_types=(MessageType.PUT_END, MessageType.GET_END),
    progress: ProgressFn = None,
    start_offset: Optional[int] = None,
) -> tuple[int, protocol.Frame]:
    """循环接收 DATA 帧，解密后写入 ``store``；遇到结束帧返回。

    返回 ``(本次收到的明文字节数, 结束帧)``，由调用方根据结束帧类型决定回什么 ACK。
    """
    info = FileInfo(
        file_id=store.meta.file_id,
        name=store.meta.name,
        size=store.meta.size,
        sha256=store.meta.sha256,
        chunk_size=store.meta.chunk_size,
    )
    base = start_offset if start_offset is not None else store.next_offset
    received = 0

    while True:
        frame = protocol.recv_frame(sock)

        if frame.type == MessageType.DATA:
            offset, ciphertext = protocol.unpack_data_payload(frame.payload)
            aad = crypto.chunk_aad(info.file_id, offset)
            try:
                plaintext = crypto.aes_gcm_decrypt(enc_key, ciphertext, aad)
            except ValueError as exc:
                raise TransferError(f"数据块 {offset} 认证失败：{exc}") from exc
            if offset + len(plaintext) > info.size:
                raise TransferError(f"数据块越界：{offset}+{len(plaintext)} > {info.size}")
            store.write_chunk(offset, plaintext)
            received += len(plaintext)
            _emit(progress, received, info.size - base)

        elif frame.type == MessageType.ERROR:
            detail = protocol.parse_json(frame)
            raise TransferError(f"对端返回错误：{detail}")

        elif frame.type in end_types:
            return received, frame

        else:
            raise ProtocolError(f"传输中收到意外帧类型：0x{frame.type:02x}")


def finalize_received(store: ResumeStore, expected_sha256: Optional[str] = None):
    """校验并转正接收到的文件。返回 ``(最终路径, 实际SHA256, 是否通过)``。"""
    if expected_sha256 and store.meta.sha256 != expected_sha256:
        store.meta.sha256 = expected_sha256
    return store.finish(verify=True)


def make_store(
    dest_dir, info: FileInfo, prev_meta: Optional[dict] = None
) -> ResumeStore:
    """构造（并按需恢复）一个 ``ResumeStore``。

    ``prev_meta`` 是断线前保存下来的元数据；若 ``file_id`` 与本次一致，
    则续用原 ``.part``，实现真正的断点续传。
    """
    store = ResumeStore(
        dest_dir=dest_dir,
        file_id=info.file_id,
        name=info.name,
        size=info.size,
        sha256=info.sha256,
        chunk_size=info.chunk_size,
    )
    store.load()
    return store
