"""命令行端到端验证：拉起真实的 cli_server.py 子进程，用真实的 cli_client.py 驱动。

验证内容：
  1. 上传成功且退出码 0，服务端落盘文件与源文件逐字节一致
  2. 下载成功且退出码 0，客户端落盘文件与源文件逐字节一致
  3. 错误口令退出码 1（且服务端不崩，仍能继续服务）
  4. 长连接复用：一次 shell 会话内连续 put/get 两个文件都成功
  5. 完成后服务端接收目录不留 .part / .part.meta.json 残骸

用法（在项目根目录）：
    ./.venv/Scripts/python.exe verify_cli_e2e.py
成功打印 CLI_E2E_OK 并以 0 退出，失败打印原因并以 1 退出。
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = Path(sys.executable)
PASSWORD = "verify-cli-pwd"
PORT = 0  # 运行时挑一个空闲端口


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_client(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(PY), str(ROOT / "cli_client.py"), "--host", "127.0.0.1", "--port", str(PORT),
         "--password", PASSWORD, "--data-dir", str(DATA), *args],
        cwd=str(ROOT), capture_output=True, text=True, timeout=120,
    )


def payload(size: int, seed: int) -> bytes:
    return bytes((i * (seed + 3) + seed) % 256 for i in range(size))


def main() -> int:
    global PORT, DATA

    tmp = Path(tempfile.mkdtemp(prefix="sft_cli_e2e_"))
    DATA = tmp / "data"
    share = DATA / "share"
    share.mkdir(parents=True, exist_ok=True)
    PORT = free_port()

    files = {"alpha.bin": 250000, "beta.bin": 64 * 1024 + 7}
    for name, size in files.items():
        (share / name).write_bytes(payload(size, size % 251))

    log_path = tmp / "server.log"
    log_fh = open(log_path, "w", encoding="utf-8")
    server = subprocess.Popen(
        [str(PY), str(ROOT / "cli_server.py"), "--host", "127.0.0.1", "--port", str(PORT),
         "--password", PASSWORD, "--data-dir", str(DATA), "--log-level", "INFO"],
        cwd=str(ROOT), stdout=log_fh, stderr=subprocess.STDOUT,
    )

    failures: list[str] = []

    def check(cond: bool, label: str, detail: str = "") -> None:
        print(("  PASS  " if cond else "  FAIL  ") + label + (f"  [{detail}]" if detail else ""))
        if not cond:
            failures.append(label + (f" ({detail})" if detail else ""))

    try:
        # 等服务端监听就绪
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=1).close()
                break
            except OSError:
                if server.poll() is not None:
                    print(server and log_path.read_text(encoding="utf-8"))
                    return 1
                time.sleep(0.2)
        else:
            print("服务端启动超时")
            print(log_path.read_text(encoding="utf-8"))
            return 1

        print("[1] 上传两个文件")
        for name in files:
            r = run_client("upload", str(share / name))
            check(r.returncode == 0, f"upload {name} 退出码为 0", f"实际 {r.returncode}")

        for name, size in files.items():
            got = DATA / "received" / name
            check(got.is_file(), f"服务端收到 {name}")
            if got.is_file():
                check(got.read_bytes() == payload(size, size % 251),
                      f"{name} 上传后逐字节一致")

        leftovers = [p.name for p in (DATA / "received").glob("*")
                     if p.name.endswith(".part") or p.name.endswith(".part.meta.json")]
        check(not leftovers, "接收目录无断点残骸", ",".join(leftovers))

        print("[2] 下载两个文件")
        for name in files:
            r = run_client("download", name)
            check(r.returncode == 0, f"download {name} 退出码为 0", f"实际 {r.returncode}")

        for name, size in files.items():
            got = DATA / "downloaded" / name
            check(got.is_file(), f"客户端下载到 {name}")
            if got.is_file():
                check(got.read_bytes() == payload(size, size % 251),
                      f"{name} 下载后逐字节一致")

        print("[3] 错误口令")
        bad = subprocess.run(
            [str(PY), str(ROOT / "cli_client.py"), "--host", "127.0.0.1", "--port", str(PORT),
             "--password", "definitely-wrong", "--data-dir", str(DATA),
             "upload", str(share / "alpha.bin")],
            cwd=str(ROOT), capture_output=True, text=True, timeout=120,
        )
        check(bad.returncode == 1, "错误口令退出码为 1", f"实际 {bad.returncode}")
        check("认证失败" in (bad.stdout + bad.stderr), "错误口令有明确提示")

        print("[4] 错误口令后服务端仍可用")
        r = run_client("download", "alpha.bin")
        check(r.returncode == 0, "服务端在拒绝认证后仍能继续服务", f"实际 {r.returncode}")

        print("[5] shell 会话内长连接复用")
        shell_in = "put %s\nget beta.bin\nquit\n" % (share / "beta.bin")
        sh = subprocess.run(
            [str(PY), str(ROOT / "cli_client.py"), "--host", "127.0.0.1", "--port", str(PORT),
             "--password", PASSWORD, "--data-dir", str(DATA), "shell"],
            cwd=str(ROOT), input=shell_in, capture_output=True, text=True, timeout=120,
        )
        check(sh.returncode == 0, "shell 会话整体退出码为 0", f"实际 {sh.returncode}")

    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append(f"异常：{exc}")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        log_fh.close()

    print("\n--- 服务端日志（尾部）---")
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-25:]:
        print(line)

    if failures:
        print("\n=== CLI_E2E_FAILED ===")
        for f in failures:
            print("  -", f)
        return 1
    print("\n=== CLI_E2E_OK ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
