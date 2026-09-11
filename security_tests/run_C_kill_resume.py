"""Red-team C: 中断后续传是否真的能恢复（作者没测这个）。
起服务端，客户端上传 50MB 文件，传到一半强制杀掉客户端进程，
断言服务端留下 .part + .part.meta.json；再起客户端重传同一文件，
断言 resumed_from>0、最终文件逐字节一致、完成后无残骸。
"""
import sys, socket, threading, subprocess, time, os
sys.path.insert(0, ".")
from app import config, transfer

ROOT = os.getcwd()
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
SIZE = 50 * 1024 * 1024  # 50 MB

src = os.path.join(ROOT, "security_tests", "big50.bin")
if not os.path.exists(src):
    with open(src, "wb") as f:
        for i in range(0, SIZE, 1024*1024):
            f.write(bytes(((j * 7 + 3) % 256) for j in range(1024*1024)))
print(f"[C] source {SIZE} bytes created", flush=True)

srv_dir = os.path.join(ROOT, "security_tests", "srvdataC")
os.makedirs(srv_dir, exist_ok=True)
srv_log = os.path.join(ROOT, "security_tests", "srvC.log")
srv = subprocess.Popen([PY, "cli_server.py", "--host", "127.0.0.1", "--port", "5013",
                        "--password", "redteam", "--data-dir", srv_dir],
                       stdout=open(srv_log, "w"), stderr=subprocess.STDOUT)
time.sleep(1.5)
recv_dir = os.path.join(srv_dir, "received")

# 第一次上传，传到一半杀掉
cli = subprocess.Popen([PY, "cli_client.py", "--host", "127.0.0.1", "--port", "5013",
                        "--password", "redteam", "upload", src],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
part_path = None
killed = False
t0 = time.time()
while time.time() - t0 < 30:
    # 找当前 .part
    parts = [p for p in os.listdir(recv_dir) if p.endswith(".part")] if os.path.isdir(recv_dir) else []
    for p in parts:
        fp = os.path.join(recv_dir, p)
        if os.path.getsize(fp) >= SIZE // 2:
            print(f"[C] .part reached {os.path.getsize(fp)} bytes, killing client", flush=True)
            cli.kill()
            killed = True
            break
    if killed:
        break
    time.sleep(0.01)
if not killed:
    cli.kill()
    print("[C] WARN: client finished before we could kill", flush=True)
out1, err1 = cli.communicate(timeout=10)

# 断言留下 .part + .part.meta.json
parts = [p for p in os.listdir(recv_dir) if p.endswith(".part")] if os.path.isdir(recv_dir) else []
metas = [p for p in os.listdir(recv_dir) if p.endswith(".part.meta.json")] if os.path.isdir(recv_dir) else []
print(f"[C] after kill: .part={parts}  meta={metas}", flush=True)
assert parts, "中断后没有留下 .part 文件"
assert metas, "中断后没有留下 .part.meta.json"

# 第二次重传同一文件（经过计数代理，证明只传缺失部分）
def run_counted(client_args, proxy_port, upstream_port):
    c2s = 0
    lock = threading.Lock()
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", proxy_port)); ls.listen(4)
    def relay(s, d, cnt):
        nonlocal c2s
        try:
            while True:
                b = s.recv(65536)
                if not b: break
                if cnt:
                    with lock: c2s += len(b)
                d.sendall(b)
        except OSError: pass
    def loop():
        c, _ = ls.accept()
        up = socket.create_connection(("127.0.0.1", upstream_port), timeout=5)
        threading.Thread(target=relay, args=(c, up, True), daemon=True).start()
        threading.Thread(target=relay, args=(up, c, False), daemon=True).start()
    th = threading.Thread(target=loop, daemon=True); th.start()
    cl = subprocess.Popen(client_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    o, e = cl.communicate(timeout=90)
    th.join(timeout=3)
    return cl.returncode, c2s, o, e

rc2, c2s2, out2, err2 = run_counted(
    [PY, "cli_client.py", "--host", "127.0.0.1", "--port", "5014",
     "--password", "redteam", "upload", src], 5014, 5013)
print(f"[C] client2 rc={rc2}  client->server bytes on 2nd upload={c2s2}", flush=True)

final = os.path.join(recv_dir, os.path.basename(src))
ok = os.path.exists(final) and open(final, "rb").read() == open(src, "rb").read()
residue = [p for p in os.listdir(recv_dir) if ".part" in p]
print(f"[C] final identical={ok}  residue(.part/.meta)={residue}", flush=True)

# 完整上传(无续传)理论字节：约 50MB + 帧头(每块 12+8+12+16=48 开销) + 握手
per_chunk = 12 + 8 + config.NONCE_BYTES + config.TAG_BYTES + config.CHUNK_SIZE
full_theory = (SIZE // config.CHUNK_SIZE) * per_chunk + (SIZE % config.CHUNK_SIZE)
print(f"[C] 整文件理论线上字节≈{full_theory}; 第二次实测={c2s2}", flush=True)

srv.terminate()
time.sleep(0.5)

assert parts and metas, "中断未留下断点现场"
assert ok, "重传后文件逐字节不一致"
assert not residue, f"完成后仍有残骸: {residue}"
assert rc2 == 0, "第二次上传非零退出"
assert c2s2 < full_theory, f"第二次上传未省流量(={c2s2}≈整文件{full_theory})"
print(f"C PASS: 强制杀掉客户端后，断点续传从断点恢复，第二次仅传 {c2s2} < {full_theory} 字节")
