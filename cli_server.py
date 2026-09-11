#!/usr/bin/env python3
"""命令行服务端入口。

多线程 TCP 服务端：主线程 ``accept()`` 循环，每个连接派发到一个 daemon 线程。

本文件只负责"工程外壳"，所有业务（认证 / 上传 / 下发 / 续传）都复用 ``app`` 包：
  - 命令行解析：显式传参优先级高于 ``ServerConfig`` 的默认值（含环境变量）
  - 日志：标准库 ``logging``，**禁止 print 输出日志**
  - 异常隔离：单个客户端崩溃绝不能拖垮服务端
  - 进度回调：节流到每完成 10% 打一条 INFO，避免刷屏
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
from pathlib import Path

# 从 ROOT 运行脚本即可 `from app import ...`，无需安装
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import config, protocol, session, transfer  # noqa: E402
from app.protocol import MessageType  # noqa: E402

logger = logging.getLogger("sft.server")

# 累计统计（多线程共享，用锁保护）
_stats_lock = threading.Lock()
STATS = {"connections": 0, "uploaded_bytes": 0, "downloaded_bytes": 0}

# 当前并发连接数（用于 max_clients 限流，抵御连接耗尽型 DoS）
_active_lock = threading.Lock()
_active = 0


def _decr_active() -> None:
    """当前连接数减一（连接关闭时调用）。"""
    global _active
    with _active_lock:
        _active -= 1


def _try_acquire_active(limit: int) -> bool:
    """尝试占用一个连接名额。

    未达上限则自增并返回 ``True``；已达上限返回 ``False``（调用方负责拒绝连接）。

    「判断 + 自增」必须在同一把锁内完成，否则并发 accept 会同时通过检查。
    **不要在主循环里直接写 ``_active += 1``** —— 那会让 ``_active`` 变成 ``main()``
    的局部变量，导致同函数内先读它的地方抛 ``UnboundLocalError``（曾真实发生）。
    """
    global _active
    with _active_lock:
        if _active >= limit:
            return False
        _active += 1
        return True


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


class _Progress:
    """进度回调（``(done, total)``）：每完成 10% 打一条 INFO。"""

    def __init__(self, label: str) -> None:
        self.label = label
        self._last_bucket = -1

    def __call__(self, done: int, total: int) -> None:
        if total <= 0:
            return
        pct = int(done * 100 / total)
        bucket = pct // 10  # 0..10，每 10% 一档
        if bucket > self._last_bucket:
            self._last_bucket = bucket
            logger.info(
                "%s 进度 %d%% (%s / %s)",
                self.label,
                pct,
                human_bytes(done),
                human_bytes(total),
            )


def handle_client(conn, addr, cfg: config.ServerConfig) -> None:
    """处理单条客户端连接（在独立线程中运行）。"""
    try:
        enc_key, _ = session.server_handshake(
            conn, cfg.password, cfg.pbkdf2_iterations
        )
        logger.info("客户端 %s 认证通过", addr)

        running = True
        while running:
            frame = session.next_request_frame(conn)
            if frame.type == MessageType.PUT_BEGIN:
                cb = _Progress(f"上传[{addr}]")
                res = session.handle_upload(
                    conn, enc_key, cfg.recv_dir, progress=cb, first_frame=frame
                )
                with _stats_lock:
                    STATS["uploaded_bytes"] += res.get(
                        "size", res.get("received_bytes", 0)
                    )
                logger.info("上传结束 %s: %s", res.get("name"), res.get("message"))
            elif frame.type == MessageType.GET_BEGIN:
                cb = _Progress(f"下发[{addr}]")
                res = session.handle_download(
                    conn, enc_key, cfg.share_dir, progress=cb, first_frame=frame
                )
                if res.get("ok") and "size" in res:
                    with _stats_lock:
                        STATS["downloaded_bytes"] += res["size"]
                logger.info("下发结束 %s: %s", res.get("name"), res.get("message"))
            elif frame.type == MessageType.BYE:
                logger.info("客户端 %s 主动断开 (BYE)", addr)
                break
            else:
                session.send_error(conn, f"未知请求类型 0x{frame.type:02x}")
                logger.warning(
                    "客户端 %s 发送未知请求类型 0x%02x，关闭连接", addr, frame.type
                )
                break
    except session.AuthError as exc:
        logger.warning("认证失败 %s: %s", addr, exc)
    except protocol.ProtocolError as exc:
        logger.warning("协议错误 %s: %s", addr, exc)
    except transfer.TransferError as exc:
        logger.warning("传输错误 %s: %s", addr, exc)
    except socket.timeout:
        logger.warning("连接 %s 空闲超时（%ds），已断开", addr, cfg.conn_timeout)
    except ConnectionResetError as exc:
        logger.warning("连接被重置 %s: %s", addr, exc)
    except OSError as exc:
        logger.warning("系统错误 %s: %s", addr, exc)
    finally:
        _decr_active()
        try:
            conn.close()
        except OSError:
            pass


def build_config(args: argparse.Namespace) -> config.ServerConfig:
    """命令行显式传参优先；未传的字段走 ``ServerConfig`` 默认（含环境变量）。"""
    kwargs: dict = {}
    if args.host is not None:
        kwargs["host"] = args.host
    if args.port is not None:
        kwargs["port"] = args.port
    if args.password is not None:
        kwargs["password"] = args.password
    if args.data_dir is not None:
        kwargs["data_dir"] = Path(args.data_dir).resolve()
    if args.pbkdf2_iterations is not None:
        kwargs["pbkdf2_iterations"] = args.pbkdf2_iterations
    if args.max_clients is not None:
        kwargs["max_clients"] = args.max_clients
    if args.conn_timeout is not None:
        kwargs["conn_timeout"] = args.conn_timeout
    return config.ServerConfig(**kwargs)


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="cli_server.py", description="局域网文件加密传输系统 - 服务端"
    )
    p.add_argument("--host", default=None, help="监听地址 (默认 ServerConfig: 0.0.0.0 / $SFT_HOST)")
    p.add_argument("--port", type=int, default=None, help="监听端口 (默认 5001 / $SFT_PORT)")
    p.add_argument("--password", default=None, help="认证口令 (默认 $SFT_PASSWORD 或 123456)")
    p.add_argument("--data-dir", default=None, help="数据目录 (默认 . / $SFT_DATA_DIR)")
    p.add_argument(
        "--pbkdf2-iterations", type=int, default=None, help="PBKDF2 迭代次数 (默认 200000)"
    )
    p.add_argument(
        "--max-clients", type=int, default=None,
        help="同时在线连接数上限 (默认 64 / $SFT_MAX_CLIENTS)",
    )
    p.add_argument(
        "--conn-timeout", type=int, default=None,
        help="单连接空闲超时秒数，0=不限制 (默认 300 / $SFT_CONN_TIMEOUT)",
    )
    p.add_argument("--log-level", default="INFO", help="日志级别 (默认 INFO)")
    p.add_argument(
        "--once", action="store_true", help="处理完一个连接就退出（便于自动化测试）"
    )
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    cfg = build_config(args)
    cfg.ensure_dirs()

    # 演示口令警告（安全审计用）：仍在使用兜底默认口令时醒目提示
    if cfg.using_demo_password:
        logger.warning(
            "正在使用演示默认口令 '%s'，生产环境请通过 --password 或环境变量 SFT_PASSWORD 覆盖",
            config.DEMO_PASSWORD,
        )

    # ---- 启动横幅 ----
    logger.info("=" * 64)
    logger.info("安全文件传输服务端  v%s", __import__("app").__version__)
    logger.info("监听地址: %s:%d", cfg.host, cfg.port)
    logger.info("接收目录: %s", cfg.recv_dir)
    logger.info("下发目录: %s", cfg.share_dir)
    logger.info("算法指纹: AES-256-GCM / PBKDF2-HMAC-SHA256(200000) / SHA-256")
    logger.info("分块大小: %s", human_bytes(cfg.chunk_size))
    logger.info("连接治理: max_clients=%d  conn_timeout=%ds", cfg.max_clients, cfg.conn_timeout)
    logger.info("=" * 64)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((cfg.host, cfg.port))
    listener.listen(16)

    running = True
    try:
        while running:
            try:
                conn, addr = listener.accept()
            except OSError:
                break
            # 连接数限流：达上限直接拒绝并关闭，不让其排队占线程
            if not _try_acquire_active(cfg.max_clients):
                logger.warning(
                    "连接数已达上限 %d，拒绝新连接 %s", cfg.max_clients, addr
                )
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            with _stats_lock:
                STATS["connections"] += 1
            # 空闲超时：settimeout 后 recv 超时抛 socket.timeout（OSError 子类）
            if cfg.conn_timeout > 0:
                try:
                    conn.settimeout(cfg.conn_timeout)
                except OSError:
                    pass
            t = threading.Thread(
                target=handle_client, args=(conn, addr, cfg), daemon=True
            )
            t.start()
            if args.once:
                t.join()  # 等这个连接彻底处理完再退出
                running = False
    except KeyboardInterrupt:
        logger.info("收到 KeyboardInterrupt，正在优雅退出…")
    finally:
        running = False
        try:
            listener.close()
        except OSError:
            pass
        with _stats_lock:
            logger.info("=" * 64)
            logger.info(
                "累计统计: 连接数=%d  上传=%s  下发=%s",
                STATS["connections"],
                human_bytes(STATS["uploaded_bytes"]),
                human_bytes(STATS["downloaded_bytes"]),
            )
            logger.info("=" * 64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
