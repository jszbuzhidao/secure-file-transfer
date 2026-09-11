"""verify_gui_engine.py —— 可复跑的引擎端到端验证（无界面）。

用法（在 ROOT 下）： ./.venv/Scripts/python.exe verify_gui_engine.py
成功打印 GUI_ENGINE_E2E_OK 并以 0 退出；失败以非 0 退出。

流程：启动 ServerEngine -> ClientEngine 连接 -> 上传 200000 字节随机文件
      -> 把收到的文件放入 share_dir -> 客户端按文件名下载 -> 逐字节比对。
"""
from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import gui_server  # noqa: E402
import gui_client  # noqa: E402
from app import config  # noqa: E402


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="gui_e2e_"))
    srv_cfg = config.ServerConfig(data_dir=tmp, host="127.0.0.1", port=0, password="123456")
    cli_cfg = config.ClientConfig(data_dir=tmp, host="127.0.0.1", port=0, password="123456")

    srv = gui_server.ServerEngine(cfg=srv_cfg, on_log=print)
    srv.start()  # 绑定随机空闲端口
    port = srv_cfg.port
    print(f"[verify] server listening on 127.0.0.1:{port}")

    cli = gui_client.ClientEngine(cfg=cli_cfg, on_log=print)
    cli.cfg.port = port
    if not cli.connect(password="123456"):
        print("[verify] FATAL: connect failed")
        return 1
    print("[verify] client connected")

    src = tmp / "payload.bin"
    data = os.urandom(200000)
    src.write_bytes(data)

    up = cli.upload(str(src))
    if not (up and up.get("ok")):
        print(f"[verify] FATAL: upload failed: {up}")
        return 1
    print(f"[verify] upload ok: {up.get('name')} {up.get('size')} bytes")

    recv_file = Path(up["saved_as"])
    if not recv_file.exists() or recv_file.read_bytes() != data:
        print("[verify] FATAL: UPLOAD BYTE MISMATCH")
        return 1

    srv.prepare_share(str(recv_file))  # 放入 share_dir 供客户端下载

    dl = cli.download("payload.bin")
    if not (dl and dl.get("ok")):
        print(f"[verify] FATAL: download failed: {dl}")
        return 1
    print(f"[verify] download ok: {dl.get('name')} -> {dl.get('saved_as')}")

    got = Path(dl["saved_as"])
    if not got.exists() or got.read_bytes() != data:
        print("[verify] FATAL: DOWNLOAD BYTE MISMATCH")
        return 1

    print("GUI_ENGINE_E2E_OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        for p in Path(tempfile.gettempdir()).glob("gui_e2e_*"):
            shutil.rmtree(p, ignore_errors=True)
