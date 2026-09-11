"""共享 fixtures：目录、密钥、确定性样本文件、回环 socket 对、可收集异常的后台服务端。

注意：本文件刻意仅在 ROOT 下被 pytest 加载（见 pytest.ini 的 pythonpath=.），
因此不会受到上一层目录遗留 inspect.py 对标准库的遮蔽影响。
"""

from __future__ import annotations

import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import config, crypto, protocol, session, transfer  # noqa: E402


# ---------------------------------------------------------------------------
# 目录 fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_received(tmp_path: Path) -> Path:
    d = tmp_path / "received"
    d.mkdir()
    return d


@pytest.fixture
def tmp_share(tmp_path: Path) -> Path:
    d = tmp_path / "share"
    d.mkdir()
    return d


@pytest.fixture
def tmp_download(tmp_path: Path) -> Path:
    d = tmp_path / "downloaded"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# 密码学 fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def password() -> str:
    return "test-password-123"


@pytest.fixture
def key() -> bytes:
    """32 字节随机加密密钥（AES-256）。"""
    return crypto.generate_salt(config.KEY_BYTES)


@pytest.fixture
def master_key(password: str) -> bytes:
    salt = crypto.generate_salt()
    return crypto.derive_master_key(password, salt)


@pytest.fixture
def enc_key(master_key: bytes) -> bytes:
    ek, _ = crypto.derive_subkeys(master_key)
    return ek


@pytest.fixture
def mac_key(master_key: bytes) -> bytes:
    _, mk = crypto.derive_subkeys(master_key)
    return mk


# ---------------------------------------------------------------------------
# 确定性样本文件工厂（内容可复现，便于失败定位）
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_file(tmp_path: Path):
    def _make(size: int, name: str = "sample.bin") -> Path:
        data = bytes((i * 7 + 3) % 256 for i in range(size))
        p = tmp_path / name
        p.write_bytes(data)
        return p

    return _make


# ---------------------------------------------------------------------------
# 回环 socket 对（socketpair，离线、随机端口无关）
# ---------------------------------------------------------------------------


@pytest.fixture
def loopback_pair():
    a, b = socket.socketpair()
    a.settimeout(10)
    b.settimeout(10)
    yield a, b
    a.close()
    b.close()


# ---------------------------------------------------------------------------
# 后台服务端（在独立线程里跑 accept + 分派循环）
# 把服务端线程里捕获的异常收集到 handle.errors，测试结束应断言 errors == []。
# ---------------------------------------------------------------------------


class ServerHandle:
    def __init__(self) -> None:
        self.port = 0
        self.recv_dir: Path | None = None
        self.share_dir: Path | None = None
        self.errors: list = []
        self._listener = None
        self._thread = None
        self._stop = None

    def connect(self, timeout: float = 10) -> socket.socket:
        return socket.create_connection(("127.0.0.1", self.port), timeout=timeout)


@pytest.fixture
def running_server(tmp_path: Path):
    handle = ServerHandle()
    handle.recv_dir = tmp_path / "received"
    handle.share_dir = tmp_path / "share"
    handle.recv_dir.mkdir(parents=True, exist_ok=True)
    handle.share_dir.mkdir(parents=True, exist_ok=True)
    handle._stop = threading.Event()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    handle.port = listener.getsockname()[1]
    handle._listener = listener

    srv_password = "test-password-123"

    def serve_conn(conn: socket.socket) -> None:
        conn.settimeout(15)
        try:
            enc_key, _ = session.server_handshake(conn, srv_password)
            while True:
                frame = session.next_request_frame(conn)
                if frame.type == protocol.MessageType.BYE:
                    break
                if frame.type == protocol.MessageType.PUT_BEGIN:
                    session.handle_upload(
                        conn, enc_key, handle.recv_dir, first_frame=frame
                    )
                elif frame.type == protocol.MessageType.GET_BEGIN:
                    session.handle_download(
                        conn, enc_key, handle.share_dir, first_frame=frame
                    )
                else:
                    session.send_error(conn, f"unexpected frame 0x{frame.type:02x}")
                    break
        except Exception as exc:  # noqa: BLE001 - 收集服务端异常，避免静默死掉
            handle.errors.append(exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def accept_loop() -> None:
        while not handle._stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                break
            threading.Thread(target=serve_conn, args=(conn,), daemon=True).start()

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    handle._thread = t

    yield handle

    handle._stop.set()
    try:
        listener.close()
    except Exception:
        pass
    t.join(timeout=5)
