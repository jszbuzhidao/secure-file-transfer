"""Red-team D: 内存是否真的恒定（64 KiB 流式）。
进程内用 socketpair + tracemalloc 测量接收 5MB 与 50MB 文件的峰值内存增量。
若峰值随文件大小近似线性增长 -> 流式是假的。
"""
import sys, os, socket, threading, tracemalloc
sys.path.insert(0, ".")
from app import config, crypto, protocol, transfer

CHUNK = config.CHUNK_SIZE

def make_file(path, size):
    with open(path, "wb") as f:
        for i in range(0, size, 1024*1024):
            f.write(bytes(((j * 7 + 3) % 256) for j in range(min(1024*1024, size - i))))

def measure(size):
    path = os.path.join("security_tests", f"mem{size}.bin")
    make_file(path, size)
    info = transfer.inspect_file(path)
    key = crypto.generate_salt(config.KEY_BYTES)
    recv = os.path.join("security_tests", f"recv_{size}")
    os.makedirs(recv, exist_ok=True)
    store = transfer.make_store(recv, info)

    a, b = socket.socketpair()
    def sender():
        transfer.send_file(a, key, path, info)
        protocol.send_frame(a, protocol.MessageType.PUT_END)
    t = threading.Thread(target=sender, daemon=True)
    t.start()

    tracemalloc.start()
    transfer.receive_file(b, key, store, end_types=(protocol.MessageType.PUT_END,))
    t.join(timeout=30)
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    a.close(); b.close()
    final, actual, ok = store.finish(verify=True)
    assert ok and final.read_bytes() == open(path, "rb").read(), "D: 文件不一致"
    return peak

p5 = measure(5 * 1024 * 1024)
p50 = measure(50 * 1024 * 1024)
print(f"[D] 5MB  峰值内存增量: {p5/1024:.1f} KiB")
print(f"[D] 50MB 峰值内存增量: {p50/1024:.1f} KiB")
ratio = p50 / p5 if p5 else 0
print(f"[D] 50MB/5MB 比值: {ratio:.2f}  (文件大小比值=10.0)")
verdict = "恒定(与文件大小无关)" if ratio < 3 else "疑似随文件增长(非恒定)"
print(f"[D] 结论: {verdict}")
assert ratio < 3, f"峰值内存随文件大小近似线性增长(比值{ratio})，流式/内存恒定不成立"
print("D PASS: 64 KiB 流式，内存峰值与文件大小无关")
