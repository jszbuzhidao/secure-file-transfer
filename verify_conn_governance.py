"""连接治理验证：`--max-clients` 限流 与 `--conn-timeout` 空闲超时。

这两个能力都属于「抵御连接耗尽型 DoS」的一部分，但也最容易写成**看起来有代码、
其实不生效**。所以本脚本不读源码，而是拉起真实的 `cli_server.py` 子进程、
用真实 socket 去打它的上限：

  ① 占满唯一名额后，第 2 个连接必须被**拒绝**（而不是排队占线程）
  ② 空闲超过 `conn_timeout` 的连接必须被服务端**回收**
  ③ 回收后名额必须**释放**，新连接必须能正常握手（不能漏掉名额）
  ④ 服务端日志里必须留下可追溯的 WARNING

用法（在项目根目录）：
    ./.venv/Scripts/python.exe verify_conn_governance.py

成功打印 `CONN_GOVERNANCE_OK` 并以 0 退出；失败打印原因并以 1 退出。
"""

from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = Path(sys.executable)
HOST = "127.0.0.1"
PASSWORD = "verify-conn-gov-pwd"
MAX_CLIENTS = 1
CONN_TIMEOUT = 3  # 秒，故意设很小以便快速验证

sys.path.insert(0, str(ROOT))
from app import protocol, session  # noqa: E402
from app.protocol import MessageType  # noqa: E402

RESULTS: list[tuple[bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((bool(ok), name))
    suffix = f"  [{detail}]" if detail else ""
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{suffix}")


def free_port() -> int:
    s = socket.socket()
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def handshake_with_retry(port: int, timeout: float = 20.0) -> socket.socket:
    """连上并完成握手，带重试。

    重试是为了兼容两种正常情况：服务端还没开始监听；或启动瞬间的空闲探测
    连接还没释放名额（`max_clients` 只有 1）。真正被限流拒绝时上层另有断言。
    """
    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        sock = None
        try:
            sock = socket.create_connection((HOST, port), timeout=6)
            session.client_handshake(sock, PASSWORD)
            return sock
        except Exception as exc:  # noqa: BLE001 - 重试期间吞掉一切连接类异常
            last = exc
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            time.sleep(0.2)
    raise AssertionError(f"握手重试超时：{last!r}")


def is_closed(sock: socket.socket, timeout: float = 6.0) -> bool:
    """往 socket 写一帧后试探读，判断对端是否已关闭。"""
    sock.settimeout(timeout)
    try:
        protocol.send_json(sock, MessageType.HELLO, {"version": 1, "agent": "probe"})
        data = sock.recv(1)
        return data == b""
    except OSError:
        return True


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="sft_conn_gov_"))
    port = free_port()

    print("=== 启动服务端（max_clients=%d, conn_timeout=%ds）===" % (MAX_CLIENTS, CONN_TIMEOUT))
    proc = subprocess.Popen(
        [
            str(PY), str(ROOT / "cli_server.py"),
            "--host", HOST, "--port", str(port),
            "--password", PASSWORD,
            "--data-dir", str(tmp / "data"),
            "--max-clients", str(MAX_CLIENTS),
            "--conn-timeout", str(CONN_TIMEOUT),
        ],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace",
    )

    held: socket.socket | None = None
    try:
        # ---- ① 占满唯一名额 -------------------------------------------------
        print("[1] 占满唯一连接名额")
        held = handshake_with_retry(port)
        check("第 1 个连接握手成功（占满名额）", True)

        # ---- ② 第二个连接必须被拒绝 ----------------------------------------
        print("[2] 第 2 个连接必须被限流拒绝")
        rejected = False
        detail = ""
        s2 = None
        try:
            s2 = socket.create_connection((HOST, port), timeout=6)
            try:
                session.client_handshake(s2, PASSWORD)
                detail = "竟然握手成功了，限流未生效"
            except Exception as exc:  # noqa: BLE001
                rejected = True
                detail = type(exc).__name__
        except Exception as exc:  # noqa: BLE001
            rejected = True
            detail = type(exc).__name__
        finally:
            if s2 is not None:
                try:
                    s2.close()
                except OSError:
                    pass
        check("第 2 个连接被拒绝（未占用线程）", rejected, detail)

        # ---- ③ 空闲超时必须回收 --------------------------------------------
        print("[3] 空闲 %d 秒后服务端必须回收连接" % CONN_TIMEOUT)
        time.sleep(CONN_TIMEOUT + 2.0)
        check("空闲超时后原连接已被服务端关闭", is_closed(held), "对端已关闭")

        # ---- ④ 名额必须释放 -------------------------------------------------
        print("[4] 名额释放后新连接必须可用")
        fresh = None
        ok4 = False
        try:
            fresh = handshake_with_retry(port, timeout=10.0)
            ok4 = True
        except Exception as exc:  # noqa: BLE001
            print(f"      (握手失败：{exc!r})")
        check("回收后名额已释放，新连接握手成功", ok4)
        if fresh is not None:
            try:
                protocol.send_json(fresh, MessageType.BYE, {})
                fresh.close()
            except OSError:
                pass

        if held is not None:
            try:
                held.close()
            except OSError:
                pass
    finally:
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()

    log = out or ""
    print("[5] 服务端日志必须留下可追溯的 WARNING")
    check("日志出现「连接数已达上限」", "连接数已达上限" in log)
    check("日志出现「空闲超时」", "空闲超时" in log)

    passed = sum(1 for ok, _ in RESULTS if ok)
    total = len(RESULTS)
    print()
    if passed == total:
        print(f"=== CONN_GOVERNANCE_OK ({passed}/{total}) ===")
        return 0
    print(f"=== CONN_GOVERNANCE_FAILED ({passed}/{total}) ===")
    for ok, name in RESULTS:
        if not ok:
            print(f"  - {name}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
