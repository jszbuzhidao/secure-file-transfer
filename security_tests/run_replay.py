"""Red-team 额外: 主动重放攻击测试（验证宣称#4 口令不上网+抗重放）。
捕获一次合法 AUTH 应答(HMAC)，在全新会话里原样重放，期望服务端拒绝(AUTH_FAIL)。
"""
import sys, socket, subprocess, time, os
sys.path.insert(0, ".")
from app import config, protocol, crypto

ROOT = "D:/.workbuddy/2026-09-10-16-59-59/outputs/secure_file_transfer"
PY = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
srv = subprocess.Popen([PY, "cli_server.py", "--host", "127.0.0.1", "--port", "5016",
                        "--password", "redteam", "--data-dir", ROOT + "/security_tests/srvdataR"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1.5)

def connect():
    return socket.create_connection(("127.0.0.1", 5016), timeout=10)

# 第1次会话：拿到 CHALLENGE，本地算出合法 AUTH 应答（即线上会发送的 HMAC 值）
s = connect()
protocol.send_json(s, protocol.MessageType.HELLO, {"version": config.PROTOCOL_VERSION})
ch = protocol.recv_frame(s)
chal = protocol.parse_json(ch)
master = crypto.derive_master_key("redteam", bytes.fromhex(chal["salt"]), chal["iterations"])
captured_auth = crypto.build_auth_response(master, bytes.fromhex(chal["nonce"]))  # 抓到的 HMAC
s.close()

# 第2次会话：全新 nonce，重放第1次的 AUTH
s2 = connect()
protocol.send_json(s2, protocol.MessageType.HELLO, {"version": config.PROTOCOL_VERSION})
ch2 = protocol.recv_frame(s2)  # 不同 nonce
protocol.send_frame(s2, protocol.MessageType.AUTH, captured_auth)  # 重放旧应答
resp = protocol.recv_frame(s2)
s2.close()
replay_rejected = resp.type == protocol.MessageType.AUTH_FAIL
print(f"[replay] 第1次nonce={bytes.fromhex(chal['nonce']).hex()[:12]}.. "
      f"第2次nonce={bytes.fromhex(ch2['payload'].decode() if False else protocol.parse_json(ch2)['nonce']).hex()[:12]}..")
print(f"[replay] 重放旧 AUTH 到新会话 -> 响应类型=0x{resp.type:02x} "
      f"({'AUTH_FAIL=抗重放成立' if replay_rejected else 'AUTH_OK=重放成功!!'})")

# 对照：用第3次(独立)会话真实 nonce 算出的 AUTH 应当通过
s3 = connect()
protocol.send_json(s3, protocol.MessageType.HELLO, {"version": config.PROTOCOL_VERSION})
ch3 = protocol.recv_frame(s3)
chal3 = protocol.parse_json(ch3)
real_master = crypto.derive_master_key("redteam", bytes.fromhex(chal3["salt"]), chal3["iterations"])
real_auth = crypto.build_auth_response(real_master, bytes.fromhex(chal3["nonce"]))
protocol.send_frame(s3, protocol.MessageType.AUTH, real_auth)
resp3 = protocol.recv_frame(s3); s3.close()
print(f"[replay] 同会话正确 AUTH -> 响应=0x{resp3.type:02x} ({'AUTH_OK' if resp3.type==protocol.MessageType.AUTH_OK else '失败'})")

srv.terminate(); time.sleep(0.3)
assert replay_rejected, "重放攻击成功！宣称#4(抗重放)不成立"
assert resp3.type == protocol.MessageType.AUTH_OK, "对照：正确 AUTH 反而被拒，异常"
print("REPLAY PASS: 捕获的认证应答无法在新会话重放(抗重放成立)；口令本身从不上网")
