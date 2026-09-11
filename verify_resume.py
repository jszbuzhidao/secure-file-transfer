"""Lead 独立校验：断点续传是否真的从断点开始传（而不是悄悄重传）。

思路：
  1. 造 3 个 chunk 的文件；
  2. 在服务端 recv_dir 里手工摆一个 .part + meta，只写第 0 块（模拟"上次传到 1/3 断了"）；
  3. 客户端正常上传；
  4. 断言服务端协商出的 offset == CHUNK_SIZE（真的续传），且最终文件逐字节一致。

同时统计网络侧实际传输的 DATA 字节数，证明"没重传"。
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

from app import session, transfer  # noqa: E402
from app.config import CHUNK_SIZE  # noqa: E402
from app.protocol import HEADER_SIZE, MessageType, recv_frame  # noqa: E402
from app.resume_store import ResumeStore  # noqa: E402

PASSWORD = "resume-check"
LOG: list[str] = []


def server(listener, recv_dir, stop_after=1):
    handled = 0
    while handled < stop_after:
        conn, _ = listener.accept()
        with conn:
            try:
                enc_key, _ = session.server_handshake(conn, PASSWORD)
                result = session.handle_upload(conn, enc_key, recv_dir)
                LOG.append(f"handle_upload -> {result}")
                LOG.append(f"SERVER_SAW_RESUMED_FROM={result.get('resumed_from')}")
            except Exception:  # noqa: BLE001
                LOG.append("SERVER EXC:\n" + traceback.format_exc())
                break
        handled += 1


def relay(src_sock, dst_sock, counter):
    """把 src 收到的字节原样转发给 dst，顺便统计方向流量。"""
    try:
        while True:
            buf = src_sock.recv(65536)
            if not buf:
                break
            counter["bytes"] += len(buf)
            dst_sock.sendall(buf)
    except OSError:
        pass
    finally:
        for s in (src_sock, dst_sock):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def sniffing_proxy(proxy_listener, target_port, counter):
    """一个纯转发代理，用来在客户端→服务端方向上做独立字节统计。"""
    client, _ = proxy_listener.accept()
    upstream = socket.create_connection(("127.0.0.1", target_port), timeout=20)
    t1 = threading.Thread(target=relay, args=(client, upstream, counter), daemon=True)
    t2 = threading.Thread(target=relay, args=(upstream, client, {"bytes": 0}), daemon=True)
    t1.start()
    t2.start()
    t1.join()


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sft_resume_"))
    recv_dir = tmp / "received"
    recv_dir.mkdir(parents=True)

    size = 3 * CHUNK_SIZE
    src = tmp / "big.bin"
    src.write_bytes(bytes((i * 31 + 7) % 256 for i in range(size)))

    info = transfer.inspect_file(src)
    print(f"file size={info.size} chunk={info.chunk_size} id={info.file_id[:16]}...")

    # --- 手工制造"上次传到 1/3 就断了"的现场 ---
    store = ResumeStore(
        dest_dir=recv_dir,
        file_id=info.file_id,
        name=info.name,
        size=info.size,
        sha256=info.sha256,
        chunk_size=info.chunk_size,
    )
    first_chunk = src.read_bytes()[:CHUNK_SIZE]
    store.write_chunk(0, first_chunk)
    print(f"伪造断点: part={store.part_path.name} next_offset={store.next_offset}")
    store.close()
    assert store.next_offset == CHUNK_SIZE, "断点现场构造失败"

    # --- 起服务端 ---
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    threading.Thread(target=server, args=(listener, recv_dir), daemon=True).start()

    # --- 起中间代理，独立统计客户端→服务端的原始字节 ---
    proxy_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_listener.bind(("127.0.0.1", 0))
    proxy_listener.listen(2)
    proxy_port = proxy_listener.getsockname()[1]
    counter = {"bytes": 0}
    threading.Thread(
        target=sniffing_proxy, args=(proxy_listener, port, counter), daemon=True
    ).start()

    # --- 客户端经代理上传 ---
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=20)
    enc_key, _ = session.client_handshake(sock, PASSWORD)
    result = session.request_upload(sock, enc_key, src)
    sock.close()

    print("upload result:", result)
    # 每个 DATA 帧的线上开销 = 12 字节帧头 + 8 字节 offset + 12 nonce + 16 tag = 48
    # 握手 + PUT_BEGIN/PUT_RESUME/PUT_END/PUT_ACK 也都是小帧，量级上可忽略
    print(f"线上总字节(客户端→服务端) = {counter['bytes']}")
    print(f"整文件密文理论值 ≈ {size + 3 * 48} 字节；只续传 2/3 应 ≈ {2 * CHUNK_SIZE + 2 * 48} 字节")

    ok = True
    if result.get("resumed_from") != CHUNK_SIZE:
        print(f"!! resumed_from={result.get('resumed_from')}，期望 {CHUNK_SIZE}")
        ok = False

    # 若发生重传，线上字节数会接近整文件；续传则应显著小于整文件
    full_file_wire = size + 3 * 48
    if counter["bytes"] >= full_file_wire * 0.95:
        print(f"!! 线上字节 {counter['bytes']} 接近整文件 {full_file_wire}，疑似重传")
        ok = False

    got = recv_dir / "big.bin"
    if not got.exists():
        print("!! 最终文件不存在")
        ok = False
    else:
        same = got.read_bytes() == src.read_bytes()
        print(f"逐字节一致: {same}")
        ok = ok and same
        leftovers = [p.name for p in recv_dir.iterdir() if p.name != "big.bin"]
        print(f"残留断点文件: {leftovers or '无'}")
        if leftovers:
            print("!! 完成后应清理 .part 与 meta")
            ok = False

    print("\n--- server log ---")
    for line in LOG:
        print(line)

    print("\n=== RESUME CHECK", "PASSED" if ok else "FAILED", "===")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
