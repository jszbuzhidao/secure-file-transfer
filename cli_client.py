#!/usr/bin/env python3
"""命令行客户端入口。

子命令：
  upload <文件...>   上传一个或多个文件
  download <文件名>  从服务端下发一个文件
  shell              交互式：put <路径> / get <名称> / ls / quit

设计要点：
  - 连接后 ``client_handshake``，之后所有请求**复用同一条长连接**（原课设即长连接双向）
  - 进度条纯标准库实现（不引入 tqdm）；非 TTY（管道）自动退化为按行打印
  - 口令来源顺序：``--password`` > 环境变量 ``SFT_PASSWORD`` > ``getpass`` 交互输入
  - 退出码：全部成功 0，任一请求失败 1（便于脚本 / CI 判断）

注意：服务端协议没有"列目录"消息，因此 ``ls`` 只打印本地下载目录里已下载的文件，
远端文件需知道文件名后用 ``get`` 获取（help 里也说明了这一点）。
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import socket
import sys
import time
from pathlib import Path

# 从 ROOT 运行脚本即可 `from app import ...`，无需安装
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import config, protocol, session, transfer  # noqa: E402
from app.protocol import MessageType  # noqa: E402

logger = logging.getLogger("sft.client")


def human_bytes(n: int) -> str:
    """把字节数转成人可读单位（B / KiB / MiB / GiB / TiB）。"""
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(n)
    idx = 0
    while size >= 1024.0 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(size)} {units[idx]}"
    return f"{size:.1f} {units[idx]}"


class ProgressBar:
    """纯标准库进度条。

    TTY：用 ``\\r`` 原地刷新，形如 ``[████████░░░░░░░░]  62.5%  1.2 MiB/1.9 MiB``。
    非 TTY：每完成 10% 打印一行，避免刷出大量回车。
    """

    BAR_WIDTH = 20

    def __init__(self, label: str, total: int, tty: bool) -> None:
        self.label = label
        self.total = total
        self.tty = tty
        self._last_bucket = -1
        self._start = time.monotonic()

    def __call__(self, done: int, total: int) -> None:
        if total > 0:
            self.total = total
        pct = (done * 100.0 / self.total) if self.total > 0 else 100.0
        filled = int(self.BAR_WIDTH * pct / 100.0)
        filled = max(0, min(self.BAR_WIDTH, filled))
        bar = "█" * filled + "░" * (self.BAR_WIDTH - filled)
        line = f"[{bar}]  {pct:5.1f}%  {human_bytes(done)}/{human_bytes(self.total)}"
        if self.tty:
            sys.stderr.write(f"\r{self.label} {line}")
            sys.stderr.flush()
        else:
            bucket = int(pct) // 10
            if bucket > self._last_bucket:
                self._last_bucket = bucket
                sys.stderr.write(f"{self.label} {line}\n")
                sys.stderr.flush()

    def finish(self) -> None:
        """完成时收尾：TTY 补一个换行，并打印耗时与平均速率。"""
        elapsed = time.monotonic() - self._start
        size = self.total
        rate = size / elapsed if elapsed > 0 else 0
        verdict = f"  耗时 {elapsed:.2f}s  平均速率 {human_bytes(int(rate))}/s"
        if self.tty:
            sys.stderr.write("\n" + verdict + "\n")
        else:
            sys.stderr.write(verdict + "\n")
        sys.stderr.flush()


def is_tty() -> bool:
    return sys.stderr.isatty()


def resolve_password(cli_password: str | None) -> str:
    """口令来源顺序：--password > $SFT_PASSWORD > getpass 交互。"""
    if cli_password:
        return cli_password
    env = os.getenv("SFT_PASSWORD")
    if env:
        return env
    return getpass.getpass("请输入传输口令: ")


def build_config(args: argparse.Namespace) -> config.ClientConfig:
    kwargs: dict = {}
    if args.host is not None:
        kwargs["host"] = args.host
    if args.port is not None:
        kwargs["port"] = args.port
    if args.data_dir is not None:
        kwargs["data_dir"] = Path(args.data_dir).resolve()
    return config.ClientConfig(**kwargs)


def connect(cfg: config.ClientConfig) -> socket.socket:
    return socket.create_connection((cfg.host, cfg.port), timeout=30)


def _safe_request(sock, enc_key, fn, cli_cfg, name, bar):
    """统一执行一个请求，捕获业务异常并打日志；返回 (ok, result)。"""
    try:
        return True, fn(sock, enc_key, name, cli_cfg.download_dir, progress=bar)
    except (
        session.AuthError,
        session.SessionError,
        transfer.TransferError,
        protocol.ProtocolError,
        ConnectionError,
        OSError,
    ) as exc:
        bar.finish()
        sys.stderr.write(f"\n{name} 失败: {exc}\n")
        return False, None


def cmd_upload(sock, enc_key, cli_cfg, paths) -> bool:
    ok = True
    for path in paths:
        src = Path(path)
        if not src.is_file():
            sys.stderr.write(f"文件不存在: {path}\n")
            ok = False
            continue
        bar = ProgressBar(f"上传 {src.name}", src.stat().st_size, is_tty())
        try:
            res = session.request_upload(sock, enc_key, src, progress=bar)
        except (
            session.AuthError,
            session.SessionError,
            transfer.TransferError,
            protocol.ProtocolError,
            ConnectionError,
            OSError,
        ) as exc:
            bar.finish()
            sys.stderr.write(f"\n上传失败 {src.name}: {exc}\n")
            ok = False
            continue
        bar.finish()
        if not res.get("ok"):
            sys.stderr.write(f"\n上传校验未通过 {src.name}: {res.get('message')}\n")
            ok = False
            continue
        sys.stderr.write(
            f"上传完成 {src.name} -> {res.get('saved_as')} "
            f"({human_bytes(res.get('size', 0))}, sha256={res.get('sha256', '')[:16]}…)\n"
        )
    return ok


def cmd_download(sock, enc_key, cli_cfg, name) -> bool:
    bar = ProgressBar(f"下载 {name}", 0, is_tty())  # total 待 GET_INFO 到达后更新
    try:
        res = session.request_download(
            sock, enc_key, name, cli_cfg.download_dir, progress=bar
        )
    except (
        session.AuthError,
        session.SessionError,
        transfer.TransferError,
        protocol.ProtocolError,
        ConnectionError,
        OSError,
    ) as exc:
        bar.finish()
        sys.stderr.write(f"\n下载失败 {name}: {exc}\n")
        return False
    bar.finish()
    if not res.get("ok"):
        sys.stderr.write(f"\n下载校验未通过 {name}: {res.get('message')}\n")
        return False
    sys.stderr.write(
        f"下载完成 {name} -> {res.get('saved_as')} "
        f"({human_bytes(res.get('size', 0))}, sha256={res.get('sha256', '')[:16]}…)\n"
    )
    return True


def cmd_shell(cli_cfg: config.ClientConfig, password: str) -> int:
    try:
        sock = connect(cli_cfg)
    except OSError as exc:
        sys.stderr.write(f"无法连接 {cli_cfg.host}:{cli_cfg.port}: {exc}\n")
        return 1
    try:
        enc_key, _ = session.client_handshake(sock, password)
    except session.AuthError as exc:
        sys.stderr.write(f"认证失败: {exc}\n")
        sock.close()
        return 1
    print("已连接。命令: put <路径> / get <名称> / ls / quit")
    print("提示: 远端无列目录接口，ls 仅显示本地下载目录；远端文件需已知文件名。")
    rc = 0
    while True:
        try:
            line = input("sft> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split(None, 1)
        cmd = parts[0].lower()
        if cmd in ("quit", "exit"):
            break
        elif cmd == "ls":
            d = cli_cfg.download_dir
            files = sorted(d.iterdir()) if d.is_dir() else []
            if not files:
                print("  本地下载目录为空（远端文件需知道文件名后用 get 获取）")
            else:
                for f in files:
                    print(f"  {f.name}  {human_bytes(f.stat().st_size)}")
        elif cmd == "put":
            if len(parts) < 2:
                print("用法: put <路径>")
                continue
            if not cmd_upload(sock, enc_key, cli_cfg, [parts[1]]):
                rc = 1
        elif cmd == "get":
            if len(parts) < 2:
                print("用法: get <名称>")
                continue
            if not cmd_download(sock, enc_key, cli_cfg, parts[1]):
                rc = 1
        else:
            print("未知命令。支持: put / get / ls / quit")
    # 先发 BYE 再 close
    try:
        protocol.send_json(sock, MessageType.BYE, {})
    except OSError:
        pass
    sock.close()
    print("已断开")
    return rc


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="cli_client.py", description="局域网文件加密传输系统 - 客户端"
    )
    p.add_argument("--host", default=None, help="服务端地址 (默认 127.0.0.1 / $SFT_HOST)")
    p.add_argument("--port", type=int, default=None, help="服务端端口 (默认 5001 / $SFT_PORT)")
    p.add_argument("--password", default=None, help="认证口令 (默认 $SFT_PASSWORD 或交互输入)")
    p.add_argument("--data-dir", default=None, help="数据目录 (默认 . / $SFT_DATA_DIR)")
    p.add_argument("--log-level", default="WARNING", help="日志级别 (默认 WARNING)")
    sub = p.add_subparsers(dest="command", required=True)

    p_up = sub.add_parser("upload", help="上传一个或多个文件")
    p_up.add_argument("files", nargs="+", help="要上传的文件路径（可多个）")
    p_dl = sub.add_parser("download", help="从服务端下发一个文件")
    p_dl.add_argument("name", help="服务端文件名（需已知）")
    sub.add_parser("shell", help="交互式 put/get/ls/quit")

    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.WARNING),
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    cli_cfg = build_config(args)
    cli_cfg.ensure_dirs()
    password = resolve_password(args.password)

    if args.command == "shell":
        return cmd_shell(cli_cfg, password)

    # upload / download：单条长连接，结束发 BYE
    try:
        sock = connect(cli_cfg)
    except OSError as exc:
        sys.stderr.write(f"无法连接 {cli_cfg.host}:{cli_cfg.port}: {exc}\n")
        return 1
    try:
        enc_key, _ = session.client_handshake(sock, password)
    except session.AuthError as exc:
        sys.stderr.write(f"认证失败: {exc}\n")
        sock.close()
        return 1

    ok = True
    if args.command == "upload":
        ok = cmd_upload(sock, enc_key, cli_cfg, args.files)
    elif args.command == "download":
        ok = cmd_download(sock, enc_key, cli_cfg, args.name)

    try:
        protocol.send_json(sock, MessageType.BYE, {})
    except OSError:
        pass
    sock.close()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
