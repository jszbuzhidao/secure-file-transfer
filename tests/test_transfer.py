"""transfer 层单元测试：文件元信息、分块迭代、send/receive 往返、进度、异常路径。

通过 loopback_pair 走真实 socket，验证分块加密收发在空文件/小块/大文件下都正确。
"""

from __future__ import annotations

import json
import threading

import pytest

from app import config, crypto, protocol
from app.protocol import MessageType, ProtocolError
from app.transfer import (
    FileInfo,
    TransferError,
    inspect_file,
    iter_file_chunks,
    make_store,
    receive_file,
    send_file,
)


# ---------------------------------------------------------------------------
# 元信息 / 分块迭代
# ---------------------------------------------------------------------------


def test_inspect_file(sample_file) -> None:
    p = sample_file(12345)
    info = inspect_file(p)
    assert info.file_id == info.sha256 == crypto.sha256_file(p)
    assert info.size == 12345
    d = info.to_dict()
    info2 = FileInfo.from_dict(d)
    assert (
        info2.file_id == info.file_id
        and info2.size == info.size
        and info2.sha256 == info.sha256
        and info2.chunk_size == info.chunk_size
    )


@pytest.mark.parametrize("start", [0, 100, 12345])
def test_iter_file_chunks(sample_file, start: int) -> None:
    full = sample_file(12345)
    data = full.read_bytes()
    chunks = list(iter_file_chunks(full, config.CHUNK_SIZE, start))
    assert b"".join(c for _, c in chunks) == data[start:]
    off = start
    for o, c in chunks:
        assert o == off
        off += len(c)


# ---------------------------------------------------------------------------
# send_file / receive_file 往返（参数化大小）
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "size",
    [0, 1, config.CHUNK_SIZE, config.CHUNK_SIZE + 1, 3 * config.CHUNK_SIZE + 12345],
)
def test_send_receive_roundtrip(loopback_pair, sample_file, tmp_path, size: int) -> None:
    a, b = loopback_pair
    p = sample_file(size, name=f"f{size}.bin")
    data = p.read_bytes()
    info = inspect_file(p)
    key = crypto.generate_salt(config.KEY_BYTES)
    store = make_store(tmp_path / "recv", info)

    def sender() -> None:
        send_file(a, key, p, info)
        protocol.send_frame(a, MessageType.PUT_END)

    t = threading.Thread(target=sender, daemon=True)
    t.start()
    received, frame = receive_file(
        b, key, store, end_types=(MessageType.PUT_END,)
    )
    t.join(timeout=10)
    assert frame.type == MessageType.PUT_END
    final, actual, ok = store.finish(verify=True)
    assert ok is True
    # 0 字节文件不会有任何 DATA 帧，.part 从未被创建；finish() 必须补出空文件而不是
    # 在 sha256_file 上抛 FileNotFoundError（这一条曾经是真实缺陷，现已修复并被本用例锁死）。
    assert actual == crypto.sha256_file(p)
    assert final.read_bytes() == data
    assert final.stat().st_size == size
    # 收尾必须干净：不留 .part / .part.meta.json 残骸
    leftovers = sorted(q.name for q in (tmp_path / "recv").iterdir() if q.name != final.name)
    assert leftovers == []


def test_progress_callback(loopback_pair, sample_file, tmp_path) -> None:
    a, b = loopback_pair
    size = 3 * config.CHUNK_SIZE + 123
    p = sample_file(size, name="prog.bin")
    data = p.read_bytes()
    info = inspect_file(p)
    key = crypto.generate_salt(config.KEY_BYTES)
    store = make_store(tmp_path / "recv", info)

    calls: list[tuple[int, int]] = []

    def prog(done: int, total: int) -> None:
        calls.append((done, total))

    def sender() -> None:
        send_file(a, key, p, info)
        protocol.send_frame(a, MessageType.PUT_END)

    t = threading.Thread(target=sender, daemon=True)
    t.start()
    receive_file(b, key, store, end_types=(MessageType.PUT_END,), progress=prog)
    t.join(timeout=10)

    assert len(calls) > 0
    dones = [d for d, _ in calls]
    assert dones == sorted(dones)  # 单调递增
    assert dones[-1] == size  # 最后一次 done == 本次应传总字节数


def test_receive_error_frame_raises(loopback_pair, tmp_path) -> None:
    a, b = loopback_pair
    info = FileInfo("fid", "x.bin", 100, "s" * 64, config.CHUNK_SIZE)
    store = make_store(tmp_path / "recv", info)
    protocol.send_frame(
        a, MessageType.ERROR, json.dumps({"message": "boom"}).encode()
    )
    with pytest.raises(TransferError):
        receive_file(
            b, crypto.generate_salt(config.KEY_BYTES), store,
            end_types=(MessageType.PUT_END,),
        )


def test_receive_unexpected_frame_raises(loopback_pair, tmp_path) -> None:
    a, b = loopback_pair
    info = FileInfo("fid", "x.bin", 100, "s" * 64, config.CHUNK_SIZE)
    store = make_store(tmp_path / "recv", info)
    protocol.send_frame(a, MessageType.PUT_BEGIN, b"{}")
    with pytest.raises(ProtocolError):
        receive_file(
            b, crypto.generate_salt(config.KEY_BYTES), store,
            end_types=(MessageType.PUT_END,),
        )


def test_receive_out_of_bounds_raises(loopback_pair, tmp_path) -> None:
    a, b = loopback_pair
    size = config.CHUNK_SIZE
    info = FileInfo("fid", "x.bin", size, "s" * 64, config.CHUNK_SIZE)
    store = make_store(tmp_path / "recv", info)
    key = crypto.generate_salt(config.KEY_BYTES)
    plaintext = b"Q" * config.CHUNK_SIZE
    # 偏移 1 + 块长 > size -> 越界
    ct = crypto.aes_gcm_encrypt(key, plaintext, crypto.chunk_aad(info.file_id, 1))
    payload = protocol.pack_data_payload(1, ct)
    protocol.send_frame(a, MessageType.DATA, payload)
    protocol.send_frame(a, MessageType.PUT_END)
    with pytest.raises(TransferError):
        receive_file(
            b, key, store, end_types=(MessageType.PUT_END,)
        )
