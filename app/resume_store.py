"""断点续传存储层。

原版**完全没有断点续传**：一旦传输中断，已收到的数据全废，必须从头再传一遍。
（简历上写的"断点续传"是不属实的，这个模块就是为了把它变成真的。）

实现方式：

* 接收端不直接写目标文件，而是写 ``<文件名>.<file_id前8位>.part``；
* 同时在 ``.part.meta.json`` 里记录 ``file_id`` / ``size`` / ``sha256`` / 已落盘块偏移；
* 重传时先把 meta 读回来，算出「已连续收到多少字节」，只请求剩余部分；
* 全部块到齐后再校验整文件 SHA-256，通过才 ``os.replace`` 原子重命名为正式文件。

关键点是 ``next_offset`` 必须返回**连续前缀长度**而不是最大偏移 ——
网络乱序或丢块时，中间的空洞不能被当成"已收到"，否则文件静默损坏。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto

# ---------------------------------------------------------------------------
# 同一目标文件的写入串行化
# ---------------------------------------------------------------------------
#
# 服务端是多线程的，两个客户端**同时上传同一个文件**时，`file_id` 相同 ⇒
# `.part` 与 `.part.meta.json` 是同一组路径。若不加约束，两个线程会各自持有
# 一个文件句柄交替 seek/write，并把 `received` 列表互相覆盖 —— 结果是文件
# 静默损坏。这里用「按 .part 路径取锁」把并发写同一目标的会话串行化。
#
# 注意这是**进程内**锁：单进程多线程（本项目 cli_server.py / gui_server.py 的模型）
# 足够；跨进程部署应换成文件锁（如 filelock / fcntl.flock）。
_LOCKS: dict = {}
_LOCKS_GUARD = threading.Lock()


def part_lock(path) -> threading.RLock:
    """取得某个 ``.part`` 路径对应的可重入锁（首次访问时创建）。"""
    key = os.fspath(path)
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
        return lock


def target_lock(dest_dir, name: str) -> threading.RLock:
    """取得某个**成品文件**对应的会话锁，用于串行化「同一目标的整个上传会话」。

    为什么需要它（Windows 实测踩出来的）：`os.replace(part, final)` 要求源文件
    当前没有任何打开的句柄。多个会话并发上传同一内容时，各自都开着同一个 `.part`，
    于是除了一个赢家，其余全部报
    ``PermissionError: [WinError 32] 另一个程序正在使用此文件``。

    仅靠"写每个块时加锁"解决不了，因为并发会话会在赢家重命名之后又新建出一个
    残缺的 `.part`。所以这里把**从「判断是否已存在」到「校验转正」的整段**串行化：
    排在后面的会话拿到锁后会看到成品已就位，直接零流量短路成功。
    """
    key = os.path.join(os.fspath(dest_dir), os.path.basename(str(name)))
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
        return lock


@dataclass
class PartMeta:
    """``.part`` 文件的元数据。"""

    file_id: str
    name: str
    size: int
    sha256: str
    chunk_size: int
    received: list = field(default_factory=list)  # 已落盘块的起始偏移（升序）

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id,
            "name": self.name,
            "size": self.size,
            "sha256": self.sha256,
            "chunk_size": self.chunk_size,
            "received": self.received,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PartMeta":
        return cls(
            file_id=data["file_id"],
            name=data["name"],
            size=int(data["size"]),
            sha256=data["sha256"],
            chunk_size=int(data["chunk_size"]),
            received=sorted(int(x) for x in data.get("received", [])),
        )


class ResumeStore:
    """管理一个待接收文件的 ``.part`` 与元数据，支持跨会话续传。"""

    def __init__(
        self,
        dest_dir,
        file_id: str,
        name: str,
        size: int,
        sha256: str,
        chunk_size: int,
    ) -> None:
        self.dest_dir = Path(dest_dir)
        self.dest_dir.mkdir(parents=True, exist_ok=True)
        self.meta = PartMeta(
            file_id=file_id,
            name=os.path.basename(name),
            size=size,
            sha256=sha256,
            chunk_size=chunk_size,
            received=[],
        )
        safe_name = self.meta.name.replace(os.sep, "_").replace("/", "_")
        tag = file_id[:8]
        self.part_path = self.dest_dir / f"{safe_name}.{tag}.part"
        self.meta_path = self.dest_dir / f"{safe_name}.{tag}.part.meta.json"
        self._fh = None
        # 同一 .part 的写入串行化（防同 file_id 并发上传互相踩踏）
        self._lock = part_lock(self.part_path)
        # 防御：chunk_size 为 0 会让 next_offset / missing_ranges 死循环
        if self.meta.chunk_size <= 0:
            raise ValueError(f"chunk_size 必须为正数，收到 {self.meta.chunk_size}")
        if self.meta.size < 0:
            raise ValueError(f"size 不能为负，收到 {self.meta.size}")

    # -- 恢复 ---------------------------------------------------------------

    def load(self) -> "ResumeStore":
        """若磁盘上已有同 file_id 的断点，载入其进度，实现续传。"""
        with self._lock:
            if not self.meta_path.exists():
                return self
            try:
                data = json.loads(self.meta_path.read_text(encoding="utf-8"))
                meta = PartMeta.from_dict(data)
            except (OSError, ValueError, KeyError):
                return self
            # file_id 相同 ⇒ 是同一个文件的同一份内容，可以安全续传
            if meta.file_id == self.meta.file_id and self.part_path.exists():
                self.meta = meta
            return self

    # -- 查询 ---------------------------------------------------------------

    @property
    def next_offset(self) -> int:
        """返回**连续**已接收前缀长度，即下一次应该从哪儿开始传。"""
        offset = 0
        received = set(self.meta.received)
        while offset in received:
            offset += self.meta.chunk_size
        return min(offset, self.meta.size)

    @property
    def is_complete(self) -> bool:
        return self.next_offset >= self.meta.size

    @property
    def progress(self) -> float:
        if self.meta.size <= 0:
            return 1.0
        return min(1.0, self.next_offset / self.meta.size)

    def missing_ranges(self) -> list:
        """返回缺失的 ``(start, end)`` 区间列表（end 不含），用于多段续传。"""
        ranges = []
        offset = 0
        received = set(self.meta.received)
        total = self.meta.size
        while offset < total:
            if offset in received:
                offset += self.meta.chunk_size
                continue
            start = offset
            while offset < total and offset not in received:
                offset += self.meta.chunk_size
            ranges.append((start, min(offset, total)))
        return ranges

    # -- 写入 ---------------------------------------------------------------

    def _open(self):
        if self._fh is None:
            self._fh = open(self.part_path, "r+b" if self.part_path.exists() else "w+b")
        return self._fh

    def write_chunk(self, offset: int, plaintext: bytes) -> None:
        """把明文块写到 ``offset`` 处，并落盘元数据。

        整个「seek→write→fsync→更新元数据」在持锁下完成，保证并发上传同一文件时
        不会出现两个线程交替写同一偏移、或元数据互相覆盖。
        """
        if offset >= self.meta.size:
            raise ValueError(f"偏移量越界：{offset} >= {self.meta.size}")
        with self._lock:
            fh = self._open()
            fh.seek(offset)
            fh.write(plaintext)
            fh.flush()
            os.fsync(fh.fileno())
            if offset not in self.meta.received:
                self.meta.received.append(offset)
                self.meta.received.sort()
            self.save_meta()

    def save_meta(self) -> None:
        """原子落盘元数据（先写临时文件再 replace，防止写一半断电）。

        注意：``.tmp`` 只是同目录内的中转文件，写完立刻被 ``os.replace`` 消费掉，
        所以正常情况下不会与 ``.part`` 一起被列出。
        """
        tmp = self.meta_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(self.meta.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        os.replace(tmp, self.meta_path)  # 原子替换

    # -- 收尾 ---------------------------------------------------------------

    def finish(self, verify: bool = True) -> tuple[Path, str, bool]:
        """校验并转正。返回 ``(最终路径, 实际 SHA-256, 是否校验通过)``。

        0 字节文件不会有任何 DATA 块，``.part`` 从未被创建，需要显式补一个空文件，
        否则 ``sha256_file`` 会抛 ``FileNotFoundError``。
        """
        with self._lock:
            self.close()
            if not self.part_path.exists():
                if self.meta.size != 0:
                    raise FileNotFoundError(f"断点文件缺失：{self.part_path}")
                self.part_path.write_bytes(b"")
            actual = crypto.sha256_file(self.part_path)
            ok = (not verify) or (actual == self.meta.sha256)
            final_path = self.dest_dir / self.meta.name
            if ok:
                os.replace(self.part_path, final_path)
                # 元数据清理属于「尽力而为」：删不掉只是丢了下一次续传的复用能力，
                # 绝不能因此把一次**已经成功**的传输判定为失败。
                self.cleanup_meta()
            return final_path, actual, ok

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None

    def cleanup_meta(self) -> bool:
        """尽力删除元数据文件。成功返回 True；失败吞掉异常返回 False。"""
        try:
            self.meta_path.unlink()
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def abort(self) -> None:
        """保留 ``.part`` 以便下次续传（不删文件）。"""
        with self._lock:
            self.close()

    def __enter__(self) -> "ResumeStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()
