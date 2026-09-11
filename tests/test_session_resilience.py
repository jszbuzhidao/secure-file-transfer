"""session 层的容错与并发测试（针对 `app/session.py` 新增/加固的分支）。

这一组用例存在的理由很具体：下面几条路径**都是真实踩过的坑**，而不是补出来的覆盖面。

1. `handle_upload` 的**内容寻址幂等短路**：`file_id` 就是内容 SHA-256，所以"同名 + 同大小
    + 同哈希"等价于内容已就位。重复投递或并发上传同一个文件时，服务端让客户端从
   `offset == size` 开始，**一个字节都不传**。本文件用 TCP 代理**独立统计线上字节数**来证明
   这一点，而不是只看返回值。
2. `resume_store.target_lock` 的**同目标会话串行化**：Windows 下 `os.replace` 要求源文件
   无任何其它打开的句柄，多个会话各持有同一个 `.part` 时会集体抛
   `PermissionError: [WinError 32]`（曾实测"6 个并发只有 1 个成功"）。锁生效后必须**全部成功**。
3. **收尾失败也必须回执**：`finish()` 抛异常时如果不回 `PUT_ACK` / `GET_ACK`，对端会一直
   阻塞在等回执，最后报出一个和真实原因毫无关系的"对端连接已断开"。
"""

from __future__ import annotations

import socket
import threading

import pytest

from app import config, crypto, protocol, resume_store, session, transfer

PASS = "test-password-123"


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def _bye(sock) -> None:
    try:
        sock.sendall(protocol.encode_frame(protocol.MessageType.BYE))
    except OSError:
        pass


def _upload_once(port: int, path) -> dict:
    """一次完整的上传会话（独立连接 + 握手 + 上传 + BYE）。"""
    sock = socket.create_connection(("127.0.0.1", port), timeout=30)
    try:
        enc_key, _ = session.client_handshake(sock, PASS)
        res = session.request_upload(sock, enc_key, path)
        _bye(sock)
        return res
    finally:
        sock.close()


class _TeeCounter:
    """一次性 TCP 透明代理，**独立统计 client→server 方向的原始字节数**。

    为什么不能只看 `res["skipped"]`：返回值是服务端自己说的，用它来证明"没传数据"
    是自证。挂一个代理在中间数字节，结论才和代码实现无关。
    """

    def __init__(self, host: str, port: int) -> None:
        self._upstream = (host, port)
        self.sent = 0  # 仅统计 client → server
        self._lis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._lis.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._lis.bind(("127.0.0.1", 0))
        self._lis.listen(8)
        self.port = self._lis.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._lis.accept()
            except OSError:
                return
            try:
                upstream = socket.create_connection(self._upstream, timeout=30)
            except OSError:
                client.close()
                continue
            threading.Thread(
                target=self._pump, args=(client, upstream, True), daemon=True
            ).start()
            threading.Thread(
                target=self._pump, args=(upstream, client, False), daemon=True
            ).start()

    def _pump(self, src, dst, count: bool) -> None:
        while True:
            try:
                chunk = src.recv(65536)
            except OSError:
                break
            if not chunk:
                break
            if count:
                self.sent += len(chunk)
            try:
                dst.sendall(chunk)
            except OSError:
                break
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._lis.close()
        except OSError:
            pass


@pytest.fixture
def proxy(running_server):
    p = _TeeCounter("127.0.0.1", running_server.port)
    yield p
    p.close()


# ---------------------------------------------------------------------------
# ① 内容寻址幂等：重复投递必须零流量
# ---------------------------------------------------------------------------


def test_upload_idempotent_skips_wire_transfer(running_server, proxy, tmp_path) -> None:
    size = 3 * config.CHUNK_SIZE
    src = tmp_path / "dup.bin"
    data = bytes((i * 11 + 5) % 256 for i in range(size))
    src.write_bytes(data)

    # 第一次：真实传输，线上字节数必须不少于文件本身
    first = _upload_once(proxy.port, src)
    assert first["ok"] is True
    assert first.get("skipped") is not True  # 第一次走的是真实传输路径
    assert proxy.sent >= size, f"首次传输只走了 {proxy.sent} 字节，代理统计可疑"
    after_first = proxy.sent

    # 第二次：同一份内容 -> 幂等短路
    second = _upload_once(proxy.port, src)
    delta = proxy.sent - after_first

    assert second["ok"] is True
    assert second["skipped"] is True
    assert second["resumed_from"] == size  # 协商偏移 == 文件大小 ⇒ 客户端不发 DATA
    assert second["sha256"] == crypto.sha256_file(src)

    # 最有力的一条：线上真的一个数据字节都没传（只剩握手/控制帧的几百字节）
    assert delta < 4096, f"幂等短路后线上仍传了 {delta} 字节"
    assert delta * 10 < size, f"{delta} 字节相对于 {size} 字节的文件没有明显减少"

    got = running_server.recv_dir / "dup.bin"
    assert got.read_bytes() == data
    assert running_server.errors == []


# ---------------------------------------------------------------------------
# ② 并发上传同一文件：不许有输家
# ---------------------------------------------------------------------------


def test_concurrent_upload_same_file_all_succeed(running_server, tmp_path) -> None:
    n = 5
    size = 3 * config.CHUNK_SIZE
    src = tmp_path / "race.bin"
    data = bytes((i * 37 + 11) % 256 for i in range(size))
    src.write_bytes(data)

    results: list[dict] = []
    failures: list[BaseException] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            res = _upload_once(running_server.port, src)
            with lock:
                results.append(res)
        except BaseException as exc:  # noqa: BLE001 - 线程里必须自己兜住，否则静默消失
            with lock:
                failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    # 回归点：曾出现 PermissionError: [WinError 32]，n 个客户端只有 1 个成功
    assert failures == [], f"并发上传出现异常：{failures!r}"
    assert len(results) == n
    assert all(r["ok"] is True for r in results), f"存在失败的回执：{results!r}"
    # 至少有一个走了幂等短路（其余是"排在锁后面、发现成品已就位"）
    assert any(r.get("skipped") is True for r in results)

    got = running_server.recv_dir / "race.bin"
    assert got.read_bytes() == data

    # 除成品外不得留下任何 .part / .meta.json / .tmp 残骸
    leftovers = sorted(
        q.name for q in running_server.recv_dir.iterdir() if q.name != "race.bin"
    )
    assert leftovers == []
    assert running_server.errors == []


# ---------------------------------------------------------------------------
# ③ 收尾失败也必须回执（上传方向）
# ---------------------------------------------------------------------------


def test_upload_incomplete_data_is_not_reported_as_success(
    running_server, tmp_path
) -> None:
    """数据没收全时绝不能回执成功——否则客户端会以为文件已完整落盘。

    手工发 PUT_BEGIN + 直接 PUT_END（一个 DATA 都不发），断言服务端如实报告缺口。
    """
    src = tmp_path / "partial.bin"
    src.write_bytes(b"x" * (2 * config.CHUNK_SIZE))
    info = transfer.inspect_file(src)

    sock = running_server.connect()
    try:
        enc_key, _ = session.client_handshake(sock, PASS)
        protocol.send_json(sock, protocol.MessageType.PUT_BEGIN, info.to_dict())
        frame = protocol.recv_frame(sock)
        assert frame.type == protocol.MessageType.PUT_RESUME  # 服务端协商从 0 开始

        # 一个 DATA 帧都不发，直接宣告结束
        protocol.send_json(sock, protocol.MessageType.PUT_END, {"file_id": info.file_id})
        ack = protocol.parse_json(protocol.recv_frame(sock))
        _bye(sock)
    finally:
        sock.close()

    assert ack["ok"] is False
    assert "不完整" in ack["message"]
    assert ack["missing_bytes"] == info.size  # 全部都缺
    assert ack["received_bytes"] == 0
    # 成品不得存在；此时一个 DATA 都没到，所以连 .part 都不会创建
    assert not (running_server.recv_dir / "partial.bin").exists()
    leftovers = [q.name for q in running_server.recv_dir.iterdir()]
    assert all(".part" in name for name in leftovers), f"出现了非断点残骸：{leftovers}"
    assert running_server.errors == []


def test_upload_finalize_failure_still_acks(
    running_server, tmp_path, monkeypatch
) -> None:
    src = tmp_path / "fail.bin"
    src.write_bytes(bytes((i * 7 + 3) % 256 for i in range(2 * config.CHUNK_SIZE)))

    def boom(self, verify: bool = True):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(resume_store.ResumeStore, "finish", boom)

    res = _upload_once(running_server.port, src)

    # 关键：客户端**拿到了回执**（不阻塞、不报"对端连接已断开"），且真实原因被透传
    assert res["ok"] is False
    assert "OSError" in res["message"]
    assert "simulated disk failure" in res["message"]

    # 断点必须保留下来，供下次续传
    parts = sorted(q.name for q in running_server.recv_dir.iterdir() if ".part" in q.name)
    assert any(name.endswith(".part") for name in parts), f"断点未保留：{parts}"

    # 服务端线程只是走了异常兜底分支，不应向 handle.errors 里塞异常
    assert running_server.errors == []


def test_upload_finalize_failure_but_content_present_is_success(
    running_server, tmp_path, monkeypatch
) -> None:
    """并发场景下"输的那一方"：自己 rename 失败，但赢家已经把内容正确落盘了。

    结果等价于成功，不该报错。
    """
    size = 2 * config.CHUNK_SIZE
    src = tmp_path / "won.bin"
    data = bytes((i * 17 + 9) % 256 for i in range(size))
    src.write_bytes(data)
    # 成品已就位（模拟"赢家"已经落盘）
    (running_server.recv_dir / "won.bin").write_bytes(data)

    calls = {"n": 0}
    real_already_present = session._already_present

    def fake_already_present(recv_dir, info):
        calls["n"] += 1
        # 第一次（幂等短路检查）故意报 False，逼代码走正常上传 + 收尾失败路径；
        # 第二次（异常兜底里的复检）返回真实结果 True -> 走并发兜底分支。
        if calls["n"] == 1:
            return False
        return real_already_present(recv_dir, info)

    def boom(self, verify: bool = True):
        raise PermissionError("[WinError 32] 另一个程序正在使用此文件")

    monkeypatch.setattr(session, "_already_present", fake_already_present)
    monkeypatch.setattr(resume_store.ResumeStore, "finish", boom)

    res = _upload_once(running_server.port, src)

    assert calls["n"] >= 2
    assert res["ok"] is True
    assert res["skipped"] is True
    assert "幂等" in res["message"]
    assert (running_server.recv_dir / "won.bin").read_bytes() == data
    assert running_server.errors == []


# ---------------------------------------------------------------------------
# ④ 下发方向的回执（客户端收文件时收尾失败 / 数据不完整）
# ---------------------------------------------------------------------------


@pytest.fixture
def captured_ack(running_server, monkeypatch):
    """包装 handle_download，抓住服务端最终收到的那个 GET_ACK 载荷。"""
    captured: dict = {}
    real = session.handle_download

    def wrapped(conn, enc_key, share_dir, progress=None, first_frame=None):
        result = real(conn, enc_key, share_dir, progress=progress, first_frame=first_frame)
        captured["ack"] = result
        return result

    monkeypatch.setattr(session, "handle_download", wrapped)
    return captured


def test_download_finalize_failure_acks_not_ok(
    running_server, tmp_path, captured_ack, monkeypatch
) -> None:
    data = b"download payload\n" * 5000
    (running_server.share_dir / "dl.bin").write_bytes(data)
    dest = tmp_path / "dl_fail"
    dest.mkdir()

    def boom(self, verify: bool = True):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(resume_store.ResumeStore, "finish", boom)

    sock = running_server.connect()
    try:
        enc_key, _ = session.client_handshake(sock, PASS)
        res = session.request_download(sock, enc_key, "dl.bin", dest)
        _bye(sock)
    finally:
        sock.close()

    # 客户端侧：拿到明确的失败原因，而不是卡死或报"连接已断开"
    assert res["ok"] is False
    assert "simulated disk failure" in res["message"]

    # 服务端侧：确实收到了 GET_ACK，且载荷标记为失败
    ack = captured_ack["ack"]
    assert ack["ok"] is False
    assert "simulated disk failure" in ack["message"]
    assert running_server.errors == []


def test_download_incomplete_data_acks_not_ok(
    running_server, tmp_path, captured_ack, monkeypatch
) -> None:
    data = b"incomplete payload\n" * 3000
    (running_server.share_dir / "inc.bin").write_bytes(data)
    dest = tmp_path / "dl_inc"
    dest.mkdir()

    # 让客户端"以为"数据不完整，逼它走 is_complete 为假的分支
    monkeypatch.setattr(
        resume_store.ResumeStore, "is_complete", property(lambda self: False)
    )

    sock = running_server.connect()
    try:
        enc_key, _ = session.client_handshake(sock, PASS)
        res = session.request_download(sock, enc_key, "inc.bin", dest)
        _bye(sock)
    finally:
        sock.close()

    assert res["ok"] is False
    assert "不完整" in res["message"]

    ack = captured_ack["ack"]
    assert ack["ok"] is False
    assert "不完整" in ack["message"]
    assert running_server.errors == []


# ---------------------------------------------------------------------------
# ⑤ 几个便宜但有意义的边界
# ---------------------------------------------------------------------------


def test_demo_password_flag() -> None:
    assert config.ServerConfig().using_demo_password is True
    assert config.ServerConfig(password="not-demo").using_demo_password is False
    assert config.ClientConfig().using_demo_password is True
    assert config.ClientConfig(password="not-demo").using_demo_password is False


def test_safe_basename_rejects_empty() -> None:
    with pytest.raises(session.SessionError):
        session._safe_basename("")
    with pytest.raises(session.SessionError):
        session._safe_basename("..")
    with pytest.raises(session.SessionError):
        session._safe_basename("../")


def test_target_lock_is_reentrant_and_per_target(tmp_path) -> None:
    lock_a = resume_store.target_lock(tmp_path, "a.bin")
    assert lock_a is resume_store.target_lock(tmp_path, "a.bin")  # 同目标 → 同一把锁
    assert lock_a is not resume_store.target_lock(tmp_path, "b.bin")
    # 可重入：同一线程可以再次进入
    with lock_a:
        with lock_a:
            assert True


def test_try_acquire_active_respects_limit(monkeypatch) -> None:
    import cli_server

    monkeypatch.setattr(cli_server, "_active", 0)
    assert cli_server._try_acquire_active(1) is True
    assert cli_server._try_acquire_active(1) is False  # 已达上限
    cli_server._decr_active()
    assert cli_server._try_acquire_active(1) is True  # 名额释放后可再次获取
    cli_server._decr_active()
