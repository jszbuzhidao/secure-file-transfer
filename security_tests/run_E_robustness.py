"""Red-team E: 服务端健壮性。
E1 恶意帧 / E2 半开连接 / E3 并发上传 / E4 文件名攻击 / E5 巨帧。
"""
import sys, os, socket, struct, threading, subprocess, time
sys.path.insert(0, ".")
from app import config, crypto, protocol, session, transfer

ROOT = os.getcwd()
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
PASS = "redteam"

srv_dir = os.path.join(ROOT, "security_tests", "srvdataE")
os.makedirs(srv_dir, exist_ok=True)
srv = subprocess.Popen([PY, "cli_server.py", "--host", "127.0.0.1", "--port", "5015",
                        "--password", PASS, "--data-dir", srv_dir],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)
recv_dir = os.path.join(srv_dir, "received")
share_dir = os.path.join(srv_dir, "share")

results = []
def rec(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"[{'OK' if ok else 'FAIL'}] E {name}: {detail}", flush=True)

def connect():
    return socket.create_connection(("127.0.0.1", 5015), timeout=10)

def upload_one(name, size):
    """用 app.session 在独立连接上传一个确定性文件，返回是否逐字节正确。"""
    p = os.path.join("security_tests", name)
    data = bytes((i * 7 + 3) % 256 for i in range(size))
    open(p, "wb").write(data)
    s = connect()
    try:
        ek, _ = session.client_handshake(s, PASS)
        res = session.request_upload(s, ek, p)
        return res.get("ok") and open(os.path.join(recv_dir, name), "rb").read() == data
    finally:
        s.close()

# ---- E1 恶意帧：连上发乱码，不发 HELLO ----
try:
    s = connect()
    s.sendall(b"\x00\x01\x02\x03" * 50)  # 脏数据
    s.close()
    time.sleep(0.3)
    ok = upload_one("e1.bin", 100000)
    rec("E1 恶意帧后服务端仍可用", ok, "上传成功" if ok else "上传失败(服务端可能崩)")
except Exception as e:
    rec("E1 恶意帧", False, f"异常 {e}")

# ---- E2 半开连接：发 HELLO 后挂住 ----
half_sock = None
try:
    half_sock = connect()
    protocol.send_json(half_sock, protocol.MessageType.HELLO, {"version": config.PROTOCOL_VERSION})
    # 不发后续帧，保持连接
    ok = upload_one("e2.bin", 100000)  # 并发另一个客户端
    rec("E2 半开连接不阻塞其它客户端", ok, "另一客户端上传成功" if ok else "被阻塞")
except Exception as e:
    rec("E2 半开连接", False, f"异常 {e}")

# ---- E3 并发：4 个客户端同时上传不同文件 ----
try:
    files = [(f"e3_{i}.bin", 200000 + i*1000) for i in range(4)]
    errs = []
    def worker(f):
        try:
            if not upload_one(f[0], f[1]):
                errs.append(f[0])
        except Exception as e:
            errs.append(f"{f[0]}:{e}")
    ts = [threading.Thread(target=worker, args=(f,)) for f in files]
    for t in ts: t.start()
    for t in ts: t.join(timeout=30)
    rec("E3 并发4文件上传", len(errs) == 0, f"失败={errs}" if errs else "全部逐字节正确")
except Exception as e:
    rec("E3 并发", False, f"异常 {e}")

# ---- E4 文件名攻击（绕过客户端，直接发原始名字）----
def attack_download(name):
    s = connect()
    try:
        ek, _ = session.client_handshake(s, PASS)
        protocol.send_json(s, protocol.MessageType.GET_BEGIN, {"name": name})
        frame = protocol.recv_frame(s)
        return frame.type == protocol.MessageType.ERROR
    finally:
        s.close()

# 用唯一哨兵基名，避免命中系统已存在的文件（如 C:\Windows\win.ini）
dl_attacks = [
    ("../../redteam_probe_a.txt", "redteam_probe_a.txt"),
    ("..\\..\\redteam_probe_b.txt", "redteam_probe_b.txt"),
    ("C:\\redteam_probe_c.txt", "redteam_probe_c.txt"),  # 绝对路径，系统里不会存在
    ("", ""),  # 空名
]
all_rejected = True
for nm, base in dl_attacks:
    try:
        r = attack_download(nm)
    except Exception as e:
        r = False
    all_rejected = all_rejected and r

# 上传穿越测试：绕过客户端，PUT_BEGIN 用 "../../redteam_up.txt"，
# 服务端必须只用 basename，落盘到 recv_dir/redteam_up.txt，绝不出 recv_dir。
def raw_upload(name, data):
    import tempfile
    tp = os.path.join("security_tests", "raw_up_tmp.bin")
    open(tp, "wb").write(data)
    s = connect()
    try:
        ek, _ = session.client_handshake(s, PASS)
        info = transfer.FileInfo(
            file_id=crypto.sha256_bytes(data), name=name, size=len(data),
            sha256=crypto.sha256_bytes(data), chunk_size=config.CHUNK_SIZE)
        protocol.send_json(s, protocol.MessageType.PUT_BEGIN, info.to_dict())
        frame = protocol.recv_frame(s)
        if frame.type != protocol.MessageType.PUT_RESUME:
            return False
        transfer.send_file(s, ek, tp, info, start_offset=0)
        protocol.send_json(s, protocol.MessageType.PUT_END,
                           {"file_id": info.file_id, "sha256": info.sha256})
        af = protocol.recv_frame(s)
        return af.type == protocol.MessageType.PUT_ACK
    finally:
        s.close()

up_ok = raw_upload("../../redteam_up.txt", b"UPLOAD-TRAVERSAL-PROBE-CONTENT")
# 断言：落盘在 recv_dir，且 share_dir 的父目录/系统根没有 redteam_up.txt
parent = os.path.dirname(recv_dir)
escaped = []
for cand in [os.path.join(parent, "redteam_up.txt"),
             os.path.join(os.path.dirname(parent), "redteam_up.txt"),
             "C:\\redteam_up.txt", "C:/redteam_up.txt"]:
    if os.path.exists(cand):
        escaped.append(cand)
landed = os.path.exists(os.path.join(recv_dir, "redteam_up.txt"))
print(f"[E4] upload-traversal landed_in_recv_dir={landed} escaped={escaped}", flush=True)

# 清理测试落盘文件，避免污染后续断言
for f in ["redteam_up.txt"]:
    fp = os.path.join(recv_dir, f)
    if os.path.exists(fp): os.remove(fp)

rec("E4 下载穿越/绝对路径/空名全部拒绝 + 上传穿越不出recv_dir",
    all_rejected and up_ok and landed and not escaped,
    f"dl_rejected={all_rejected} up_ok={up_ok} landed={landed} escaped={escaped}")

# ---- E5 巨帧：声明 payload_len = 2GB ----
try:
    s = connect()
    hdr = struct.pack(">2sBBII", config.MAGIC, config.PROTOCOL_VERSION, 0, 0, 2 * 1024 * 1024 * 1024)
    s.sendall(hdr)
    time.sleep(0.3)
    s.close()
    ok = upload_one("e5.bin", 50000)
    rec("E5 巨帧(2GB)被拒且服务端存活", ok, "上传成功(服务端未崩)" if ok else "服务端崩了")
except Exception as e:
    rec("E5 巨帧", False, f"异常 {e}")

if half_sock:
    try: half_sock.close()
    except OSError: pass
srv.terminate()
time.sleep(0.5)

failed = [r for r in results if not r[1]]
print(f"\n=== E 总结: {len(results)-len(failed)}/{len(results)} 通过, 失败 {len(failed)} ===")
assert not failed, f"E 失败项: {failed}"
print("E PASS: 服务端健壮性(恶意帧/半开/并发/文件名/巨帧)均达标")
