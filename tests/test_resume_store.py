"""resume_store 单元测试：断点续传地基。

重点：连续前缀语义（next_offset）、空洞（missing_ranges）、乱序写入、跨会话 load、
原子写 meta、边界大小、越界写入。绝不允许把空洞当成"已收到"。
"""

from __future__ import annotations

import pytest

from app import config, crypto
from app.resume_store import ResumeStore

CHUNK = config.CHUNK_SIZE


def _store(tmp_path, size, sha=None):
    sha = sha or ("x" * 64)
    return ResumeStore(tmp_path, "fid", "a.bin", size, sha, CHUNK)


def test_write_chunk_advances_offset(tmp_path) -> None:
    s = _store(tmp_path, 4 * CHUNK)
    s.write_chunk(0, b"A" * CHUNK)
    assert s.next_offset == CHUNK
    assert s.progress == pytest.approx(0.25)
    assert s.is_complete is False


def test_hole_semantics(tmp_path) -> None:
    # size=4*chunk，只写第 0 块和第 2 块
    s = _store(tmp_path, 4 * CHUNK)
    s.write_chunk(0, b"A" * CHUNK)
    s.write_chunk(2 * CHUNK, b"C" * CHUNK)
    # 连续前缀必须是 1*chunk，而不是 3*chunk
    assert s.next_offset == CHUNK
    assert s.missing_ranges() == [
        (CHUNK, 2 * CHUNK),
        (3 * CHUNK, 4 * CHUNK),
    ]
    assert s.is_complete is False


def test_out_of_order_then_complete(tmp_path) -> None:
    size = 4 * CHUNK
    s = _store(tmp_path, size, crypto.sha256_bytes(b"Z" * size))
    blocks = {
        0: b"A" * CHUNK,
        CHUNK: b"B" * CHUNK,
        2 * CHUNK: b"C" * CHUNK,
        3 * CHUNK: b"D" * CHUNK,
    }
    # 乱序写入
    for off in (3 * CHUNK, CHUNK, 0, 2 * CHUNK):
        s.write_chunk(off, blocks[off])
    assert s.is_complete is True
    content = s.part_path.read_bytes()
    expected = b"".join(blocks[o] for o in (0, CHUNK, 2 * CHUNK, 3 * CHUNK))
    assert content == expected


def test_finish_verify_ok_renames_and_cleans(tmp_path) -> None:
    size = CHUNK
    content = b"Z" * size
    s = _store(tmp_path, size, crypto.sha256_bytes(content))
    s.write_chunk(0, content)
    assert s.is_complete
    final, actual, ok = s.finish(verify=True)
    assert ok is True
    assert final.exists()
    assert not s.part_path.exists()
    assert not s.meta_path.exists()
    assert final.read_bytes() == content


def test_finish_tampered_not_renamed(tmp_path) -> None:
    size = CHUNK
    content = b"Z" * size
    s = _store(tmp_path, size, crypto.sha256_bytes(content))
    s.write_chunk(0, content)
    # 落地后篡改 .part
    with open(s.part_path, "r+b") as f:
        f.seek(0)
        f.write(b"Y")
    final, actual, ok = s.finish(verify=True)
    assert ok is False
    assert s.part_path.exists()  # 不应重命名
    assert not final.exists()  # 不应生成正式文件


def test_load_resumes_after_close(tmp_path) -> None:
    s1 = _store(tmp_path, 4 * CHUNK)
    s1.write_chunk(0, b"A" * CHUNK)
    s1.write_chunk(CHUNK, b"B" * CHUNK)
    s1.close()
    # 跨会话用同 file_id 重建并 load
    s2 = _store(tmp_path, 4 * CHUNK)
    s2.load()
    assert s2.next_offset == 2 * CHUNK
    assert s2.is_complete is False


def test_load_different_file_id_no_reuse(tmp_path) -> None:
    s1 = ResumeStore(tmp_path, "fidA", "a.bin", 4 * CHUNK, "x" * 64, CHUNK)
    s1.write_chunk(0, b"A" * CHUNK)
    s1.close()
    s2 = ResumeStore(tmp_path, "fidB", "a.bin", 4 * CHUNK, "x" * 64, CHUNK)
    s2.load()
    # 不同 file_id 不复用旧进度
    assert s2.next_offset == 0


def test_meta_atomic_no_tmp_residue(tmp_path) -> None:
    s = _store(tmp_path, CHUNK)
    s.write_chunk(0, b"A" * CHUNK)
    tmp = s.meta_path.with_suffix(".json.tmp")
    assert not tmp.exists()
    assert s.meta_path.exists()


def test_size_zero(tmp_path) -> None:
    s = ResumeStore(tmp_path, "fid", "a.bin", 0, crypto.sha256_bytes(b""), CHUNK)
    assert s.next_offset == 0
    assert s.is_complete is True
    assert s.progress == 1.0


def test_size_exactly_one_chunk(tmp_path) -> None:
    s = _store(tmp_path, CHUNK)
    s.write_chunk(0, b"A" * CHUNK)
    assert s.is_complete is True
    with pytest.raises(ValueError):
        s.write_chunk(CHUNK, b"x")  # offset >= size


def test_size_chunk_plus_one(tmp_path) -> None:
    size = CHUNK + 1
    s = _store(tmp_path, size)
    s.write_chunk(0, b"A" * CHUNK)
    s.write_chunk(CHUNK, b"Z")  # 末尾 1 字节块
    assert s.is_complete is True
    with pytest.raises(ValueError):
        s.write_chunk(size, b"x")  # offset >= size


def test_write_out_of_bounds(tmp_path) -> None:
    s = _store(tmp_path, CHUNK)
    with pytest.raises(ValueError):
        s.write_chunk(CHUNK + 10, b"x")
