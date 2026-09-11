"""session 层端到端测试：用 running_server fixture 跑真实回环链路。

覆盖：认证（正确/错误口令）、单/多文件上传、下发、目录穿越防护、断点续传、进度回调。
服务端线程异常被收集到 handle.errors，正常用例结束应断言 errors == []。
"""

from __future__ import annotations

import pytest

from app import config, crypto, protocol, session, transfer

PASS = "test-password-123"


def _bye(sock) -> None:
    try:
        sock.sendall(protocol.encode_frame(protocol.MessageType.BYE))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 认证
# ---------------------------------------------------------------------------


def test_handshake_ok(running_server) -> None:
    sock = running_server.connect()
    try:
        ek, mk = session.client_handshake(sock, PASS)
        assert ek is not None and mk is not None
        _bye(sock)
    finally:
        sock.close()
    assert running_server.errors == []


def test_handshake_wrong_password(running_server) -> None:
    sock = running_server.connect()
    try:
        with pytest.raises(session.AuthError):
            session.client_handshake(sock, "wrong-pass")
    finally:
        sock.close()

    # 服务端不得崩：新连接仍能正常握手
    sock2 = running_server.connect()
    try:
        ek, _ = session.client_handshake(sock2, PASS)
        assert ek is not None
        _bye(sock2)
    finally:
        sock2.close()

    # 唯一记录的错误就是这次预期的认证失败（服务端优雅处理，非崩溃）
    assert len(running_server.errors) == 1
    assert isinstance(running_server.errors[0], session.AuthError)


# ---------------------------------------------------------------------------
# 上传
# ---------------------------------------------------------------------------


def test_upload_single_file(running_server, tmp_path) -> None:
    size = 300 * 1024
    src = tmp_path / "payload.bin"
    data = bytes((i * 7 + 3) % 256 for i in range(size))
    src.write_bytes(data)

    sock = running_server.connect()
    try:
        ek, _ = session.client_handshake(sock, PASS)
        calls = []
        res = session.request_upload(
            sock, ek, src, progress=lambda d, t: calls.append((d, t))
        )
        assert res["ok"] is True
        assert res["sha256"] == crypto.sha256_file(src)
        assert len(calls) > 0
        assert calls[-1][0] == size  # 进度最后一次 == 总字节数
        _bye(sock)
    finally:
        sock.close()

    got = running_server.recv_dir / "payload.bin"
    assert got.exists()
    assert got.read_bytes() == data
    assert running_server.errors == []


def test_upload_two_files_same_connection(running_server, tmp_path) -> None:
    files = []
    for i in range(2):
        p = tmp_path / f"f{i}.bin"
        d = bytes((i * 13 + j * 7 + 3) % 256 for j in range(123456))
        p.write_bytes(d)
        files.append((p, d))

    sock = running_server.connect()
    try:
        ek, _ = session.client_handshake(sock, PASS)
        for p, d in files:
            res = session.request_upload(sock, ek, p)
            assert res["ok"] is True
            assert res["sha256"] == crypto.sha256_file(p)
        _bye(sock)
    finally:
        sock.close()

    for p, d in files:
        got = running_server.recv_dir / p.name
        assert got.exists()
        assert got.read_bytes() == d
    assert running_server.errors == []


# ---------------------------------------------------------------------------
# 下发
# ---------------------------------------------------------------------------


def test_download_file(running_server, tmp_path) -> None:
    src = running_server.share_dir / "server.txt"
    data = b"server side content\n" * 1000
    src.write_bytes(data)
    dest = tmp_path / "downloaded"
    dest.mkdir()

    sock = running_server.connect()
    try:
        ek, _ = session.client_handshake(sock, PASS)
        res = session.request_download(sock, ek, "server.txt", dest)
        assert res["ok"] is True
        _bye(sock)
    finally:
        sock.close()

    got = dest / "server.txt"
    assert got.exists()
    assert got.read_bytes() == data
    assert running_server.errors == []


def test_download_missing_raises(running_server, tmp_path) -> None:
    dest = tmp_path / "dl_missing"
    dest.mkdir()

    sock = running_server.connect()
    try:
        ek, _ = session.client_handshake(sock, PASS)
        with pytest.raises(transfer.TransferError):
            session.request_download(sock, ek, "nope.txt", dest)
        _bye(sock)
    finally:
        sock.close()
    assert running_server.errors == []


def test_download_path_traversal_blocked(running_server, tmp_path) -> None:
    dest = tmp_path / "dl_trav"
    dest.mkdir()

    sock = running_server.connect()
    try:
        ek, _ = session.client_handshake(sock, PASS)
        # 客户端会先把名字净化为 basename，服务端找不到文件 -> ERROR -> TransferError
        with pytest.raises(transfer.TransferError):
            session.request_download(sock, ek, "../../secret.txt", dest)
        _bye(sock)
    finally:
        sock.close()

    # 断言 share_dir 之外（含其父目录）没有被创建任何文件
    assert not (running_server.share_dir.parent / "secret.txt").exists()
    assert not (dest / "secret.txt").exists()
    assert running_server.errors == []


def test_safe_basename_defense_in_depth() -> None:
    # 服务端自身的目录穿越防护（纵深防御，即使客户端被绕过）
    from app.session import _safe_basename

    assert _safe_basename("../../secret.txt") == "secret.txt"
    assert _safe_basename("a/../../b") == "b"
    assert _safe_basename("plain.txt") == "plain.txt"
    with pytest.raises(session.SessionError):
        _safe_basename("../")


# ---------------------------------------------------------------------------
# 断点续传（最重要的端到端用例）
# ---------------------------------------------------------------------------


def test_resume_upload_from_breakpoint(running_server, tmp_path) -> None:
    size = 3 * config.CHUNK_SIZE
    src = tmp_path / "big.bin"
    data = bytes((i * 7 + 3) % 256 for i in range(size))
    src.write_bytes(data)
    info = transfer.inspect_file(src)

    # 模拟“上次传到 1/3 断了”：服务端 recv_dir 已有第 0 块 .part + meta
    store = transfer.ResumeStore(
        running_server.recv_dir,
        info.file_id,
        info.name,
        info.size,
        info.sha256,
        info.chunk_size,
    )
    store.write_chunk(0, data[: config.CHUNK_SIZE])
    store.close()

    sock = running_server.connect()
    try:
        ek, _ = session.client_handshake(sock, PASS)
        res = session.request_upload(sock, ek, src)
        # 服务端确实从断点续传，而不是重传
        assert res["resumed_from"] == config.CHUNK_SIZE
        assert res["ok"] is True
        assert res["sha256"] == info.sha256
        _bye(sock)
    finally:
        sock.close()

    got = running_server.recv_dir / info.name
    assert got.exists()
    assert got.read_bytes() == data
    assert running_server.errors == []
