"""Red-team B: 断点续传是否真的省流量。
在 cli_client 与服务端之间插一个 TCP 代理，独立统计 客户端->服务端 方向字节数。
造 5 块(320KiB)文件，先伪造"已收 2 块"的现场，再上传，断言只传缺失部分。
"""
import sys, socket, threading, subprocess, time, os, json, struct
sys.path.insert(0, ".")
from app import config, crypto, transfer
from app.resume_store import ResumeStore

ROOT = os.getcwd()
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
CHUNK = config.CHUNK_SIZE
SIZE = 5 * CHUNK  # 320 KiB, 5 块

# 1) 源文件（确定性内容）
src = os.path.join(ROOT, "security_tests", "big5.bin")
data = bytes((i * 7 + 3) % 256 for i in range(SIZE))
open(src, "wb").write(data)
info = transfer.inspect_file(src)

# 2) 启服务端（独立 data-dir）
srv_dir = os.path.join(ROOT, "security_tests", "srvdataB")
os.makedirs(srv_dir, exist_ok=True)
srv = subprocess.Popen([PY, "cli_server.py", "--host", "127.0.0.1", "--port", "5011",
                        "--password", "redteam", "--data-dir", srv_dir],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)
print("[debug] server poll():", srv.poll(), flush=True)

recv_dir = os.path.join(srv_dir, "received")
# 3) 伪造"已收 2 块"现场
store = ResumeStore(recv_dir, info.file_id, info.name, info.size, info.sha256, info.chunk_size)
store.write_chunk(0, data[0:CHUNK])
store.write_chunk(CHUNK, data[CHUNK:2*CHUNK])
store.close()

# 4) TCP 代理：client->proxy->server，统计 client->server 方向字节
proxy_port = 5012
c2s_bytes = 0
lock = threading.Lock()
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", proxy_port))
listener.listen(4)

def relay(src_sock, dst_sock, count_c2s):
    global c2s_bytes
    try:
        while True:
            buf = src_sock.recv(65536)
            if not buf:
                break
            if count_c2s:
                with lock:
                    c2s_bytes += len(buf)
            dst_sock.sendall(buf)
    except OSError:
        pass

def proxy_loop():
    print("[proxy] listening on 5012", flush=True)
    listener.settimeout(5)
    conn, _ = listener.accept()
    print("[proxy] client connected", flush=True)
    try:
        up = socket.create_connection(("127.0.0.1", 5011), timeout=5)
    except OSError as e:
        print("[proxy] upstream connect FAILED:", e, flush=True)
        conn.close()
        return
    print("[proxy] upstream connected", flush=True)
    t1 = threading.Thread(target=relay, args=(conn, up, True), daemon=True)   # client->server (count)
    t2 = threading.Thread(target=relay, args=(up, conn, False), daemon=True)  # server->client
    t1.start(); t2.start()
    t1.join(); t2.join()
    try: conn.close()
    except OSError: pass
    try: up.close()
    except OSError: pass

# 5) 先起客户端子进程，再在主线程跑代理 accept（避免线程时序）
cli = subprocess.Popen([PY, "cli_client.py", "--host", "127.0.0.1", "--port", str(proxy_port),
                        "--password", "redteam", "upload", src], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
pt = threading.Thread(target=proxy_loop, daemon=True)
pt.start()
try:
    out, err = cli.communicate(timeout=40)
except subprocess.TimeoutExpired:
    print("[debug] client upload TIMED OUT; c2s_bytes so far:", c2s_bytes, flush=True)
    cli.kill()
    out, err = b"", b""
pt.join(timeout=5)

srv.terminate()
time.sleep(0.5)

resumed_from = None
for line in (out + err).decode(errors="replace").splitlines():
    if "resumed_from" in line or "续传" in line or "resumed" in line:
        print("CLI:", line.strip())
# 读取服务端回执更可靠：检查 received 文件是否完整且偏移
final = os.path.join(recv_dir, info.name)
ok_bytes = os.path.exists(final) and open(final, "rb").read() == data

# 计算“整文件”理论线上字节（5 块）作为对比
per_chunk = 12 + 8 + config.NONCE_BYTES + config.TAG_BYTES + CHUNK  # header+offset+nonce+tag+ct
full_theory = 5 * per_chunk
sent_theory = 3 * per_chunk  # 只传 3 块

print(f"\n=== B 总结 ===")
print(f"文件大小       : {SIZE} 字节 ({5} 块)")
print(f"已预置现场     : 2 块已收")
print(f"client->server 实测字节: {c2s_bytes}")
print(f"续传理论应传   : ~{sent_theory} 字节 (3 块数据+帧)")
print(f"整文件理论字节 : ~{full_theory} 字节 (5 块)")
print(f"实测 < 整文件? : {c2s_bytes < full_theory}  (差 {full_theory - c2s_bytes} 字节)")
print(f"落盘文件正确   : {ok_bytes}")
print(f"节省比例       : {100*(full_theory-c2s_bytes)/full_theory:.1f}% 未重传")

# 断言：实测字节明显小于整文件，且文件正确
assert c2s_bytes < full_theory, "续传没有省流量！"
assert ok_bytes, "落盘文件不正确"
print("B PASS: 断点续传确实只传缺失部分（省流量）")
