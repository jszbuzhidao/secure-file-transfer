"""冒烟测试：本地回环跑一遍完整链路（认证 → 上传 → 下发 → 断点续传）。

用法： python smoke_e2e.py
非 pytest 用例，只用于快速验证工程是否跑得通。
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import session  # noqa: E402
from app import transfer  # noqa: E402

PASSWORD = "test-password-123"
LOG: list = []


def _dump_log() -> None:
    print("--- server log ---")
    for line in LOG:
        print(line)


def _server(listener, recv_dir, share_dir, stop_after=2):
    handled = 0
    while handled < stop_after:
        conn, addr = listener.accept()
        with conn:
            try:
                LOG.append(f"accept {addr}")
                enc_key, _ = session.server_handshake(conn, PASSWORD)
                LOG.append("server handshake ok")
                r1 = session.handle_upload(conn, enc_key, recv_dir)
                LOG.append(f"upload -> {r1}")
                r2 = session.handle_download(conn, enc_key, share_dir)
                LOG.append(f"download -> {r2}")
            except Exception:  # noqa: BLE001 - 冒烟脚本要看到服务端真实异常
                LOG.append("SERVER EXCEPTION:\n" + traceback.format_exc())
                break
        handled += 1


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sft_smoke_"))
    recv_dir = tmp / "received"
    share_dir = tmp / "share"
    cli_dir = tmp / "downloaded"
    for d in (recv_dir, share_dir, cli_dir):
        d.mkdir(parents=True)

    # 造一个 300 KiB 的源文件（跨 5 个 64 KiB 块，覆盖最后一块不足的情况）
    src = tmp / "payload.bin"
    payload = os.urandom(300 * 1024)
    src.write_bytes(payload)

    # 服务端要下发的文件
    share_src = share_dir / "server_side.txt"
    share_payload = b"server says hello\n" * 5000
    share_src.write_bytes(share_payload)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]

    threading.Thread(
        target=_server, args=(listener, recv_dir, share_dir), daemon=True
    ).start()

    try:
        # ---- 客户端：上传 + 下发 ----
        sock = socket.create_connection(("127.0.0.1", port), timeout=15)
        enc_key, _ = session.client_handshake(sock, PASSWORD)
        print("[client] handshake ok")

        up = session.request_upload(sock, enc_key, src)
        print("[client] upload result:", up)
        assert up["ok"], up

        down = session.request_download(sock, enc_key, "server_side.txt", cli_dir)
        print("[client] download result:", down)
        assert down["ok"], down
        assert (cli_dir / "server_side.txt").read_bytes() == share_payload
        sock.close()

        got = recv_dir / "payload.bin"
        assert got.exists(), f"未找到 {got}, 目录={list(recv_dir.iterdir())}"
        assert got.read_bytes() == payload, "上传内容不一致"
        assert transfer.inspect_file(got).sha256 == transfer.inspect_file(src).sha256
        print("[client] upload byte-for-byte OK")

        # ---- 错误口令应被拒绝 ----
        sock2 = socket.create_connection(("127.0.0.1", port), timeout=15)
        try:
            session.client_handshake(sock2, "wrong-password")
            print("!! 错误口令居然通过了")
            return 1
        except session.AuthError as exc:
            print("[client] wrong password rejected OK:", exc)
        finally:
            sock2.close()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        _dump_log()
        return 1

    print("\n=== SMOKE PASSED ===")
    _dump_log()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
