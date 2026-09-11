"""CLI 端到端测试（有效用例）。

cli_server.py / cli_client.py 位于项目 ROOT（非 app/ 包内），提供可程序化调用的：
  - cli_server.handle_client(conn, addr, cfg)   处理单条连接（与 main() 的派发逻辑一致）
  - cli_client.connect(cfg) / cmd_upload(...) / cmd_download(...)  复用同一条长连接

这里用 handle_client + cmd_upload/cmd_download 跑真实回环，验证 CLI 外壳正确复用 app 层。
若两个模块不可用，整文件被 importorskip 跳过，不会失败。
"""

from __future__ import annotations

import socket
import threading

import pytest

pytest.importorskip("cli_server")
pytest.importorskip("cli_client")

import cli_client
import cli_server
from app import config, protocol, session

PASS = "cli-pass"


def test_cli_upload_and_download_roundtrip(tmp_path) -> None:
    recv_dir = tmp_path / "received"
    share_dir = tmp_path / "share"
    recv_dir.mkdir()
    share_dir.mkdir()

    srv_cfg = config.ServerConfig(
        host="127.0.0.1", port=0, password=PASS, data_dir=tmp_path
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]

    def serve() -> None:
        conn, addr = listener.accept()
        conn.settimeout(15)
        cli_server.handle_client(conn, addr, srv_cfg)

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    # --- 客户端侧（走真实 cli_client 外壳）---
    cli_cfg = config.ClientConfig(host="127.0.0.1", port=port, data_dir=tmp_path)
    cli_cfg.ensure_dirs()  # 创建 download_dir

    src = tmp_path / "up.bin"
    src.write_bytes(bytes((i * 7 + 3) % 256 for i in range(200_000)))

    shared = share_dir / "server.txt"
    shared.write_bytes(b"server side payload\n" * 1000)

    sock = cli_client.connect(cli_cfg)
    try:
        ek, _ = session.client_handshake(sock, PASS)
        ok_up = cli_client.cmd_upload(sock, ek, cli_cfg, [str(src)])
        ok_dl = cli_client.cmd_download(sock, ek, cli_cfg, "server.txt")
        protocol.send_json(sock, protocol.MessageType.BYE, {})
    finally:
        sock.close()

    assert ok_up is True
    assert ok_dl is True
    assert (recv_dir / "up.bin").read_bytes() == src.read_bytes()
    assert (cli_cfg.download_dir / "server.txt").read_bytes() == shared.read_bytes()
    t.join(timeout=5)
