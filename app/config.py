"""集中配置层。

设计原则：**密钥不落源码**。
原版把 `KEY = b'1234567890abcdef'` 和 `VERIFY_PWD = "123456"` 直接写在 .py 里，
这是最典型的硬编码缺陷（OWASP A02 加密失败 / A05 配置错误）。
现在改为：口令从环境变量或命令行读取，密钥由 PBKDF2-HMAC-SHA256 现场派生，
源码中不再出现任何密钥常量。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# 协议与算法参数（这些是"公开参数"，不是密钥，写在源码里是安全的）
# ---------------------------------------------------------------------------

CHUNK_SIZE = 64 * 1024          # 64 KiB 分块：大文件不再一次性 read() 进内存
PBKDF2_ITERATIONS = 200_000     # PBKDF2-HMAC-SHA256 迭代次数（对抗暴力破解）
SALT_BYTES = 16                 # PBKDF2 盐长度
KEY_BYTES = 32                  # AES-256 需要 32 字节密钥
NONCE_BYTES = 12                # GCM 推荐 96 bit nonce
TAG_BYTES = 16                  # GCM 认证标签长度
MAC_BYTES = 32                  # HMAC-SHA256 输出长度
MAGIC = b"\xf7\x1a"             # 帧魔数，用于快速识别脏数据
PROTOCOL_VERSION = 2

# 工作目录名
RECV_DIR_NAME = "received"      # 服务端接收上传文件的落地目录
SHARE_DIR_NAME = "share"        # 服务端对外下发的文件目录
CLIENT_DOWN_DIR_NAME = "downloaded"

# 环境变量名（便于容器化部署）
ENV_HOST = "SFT_HOST"
ENV_PORT = "SFT_PORT"
ENV_PASSWORD = "SFT_PASSWORD"
ENV_DATA_DIR = "SFT_DATA_DIR"

# 演示用默认口令。
#
# 这是**唯一的**口令兜底值，目的是让 `python cli_server.py` 裸跑就能演示，
# 与原始课程设计保持一致（原版 `VERIFY_PWD = "123456"`）。
# 它**不是密钥** —— 真正的加密密钥由 PBKDF2(口令, 随机盐) 现场派生，每次会话都不同。
# 服务端检测到仍在使用该默认值时会打印醒目警告（见 session/cli_server 的启动横幅）。
DEMO_PASSWORD = "123456"

# 服务端连接治理默认值（防连接耗尽型 DoS）
DEFAULT_CONN_TIMEOUT = 300      # 单连接空闲超时（秒），0 表示不限制
DEFAULT_MAX_CLIENTS = 64        # 同时在线连接数上限


def _env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value else default


@dataclass
class ServerConfig:
    """服务端运行参数。"""

    host: str = field(default_factory=lambda: _env(ENV_HOST, "0.0.0.0"))
    port: int = field(default_factory=lambda: int(_env(ENV_PORT, "5001")))
    # 口令仅作为默认值兜底，生产环境请用环境变量 SFT_PASSWORD 覆盖
    password: str = field(default_factory=lambda: _env(ENV_PASSWORD, DEMO_PASSWORD))
    data_dir: Path = field(
        default_factory=lambda: Path(_env(ENV_DATA_DIR, ".")).resolve()
    )
    chunk_size: int = CHUNK_SIZE
    pbkdf2_iterations: int = PBKDF2_ITERATIONS
    conn_timeout: int = field(
        default_factory=lambda: int(_env("SFT_CONN_TIMEOUT", str(DEFAULT_CONN_TIMEOUT)))
    )
    max_clients: int = field(
        default_factory=lambda: int(_env("SFT_MAX_CLIENTS", str(DEFAULT_MAX_CLIENTS)))
    )

    @property
    def using_demo_password(self) -> bool:
        """是否仍在使用演示默认口令（供启动警告与安全审计使用）。"""
        return self.password == DEMO_PASSWORD

    @property
    def recv_dir(self) -> Path:
        return self.data_dir / RECV_DIR_NAME

    @property
    def share_dir(self) -> Path:
        return self.data_dir / SHARE_DIR_NAME

    def ensure_dirs(self) -> None:
        self.recv_dir.mkdir(parents=True, exist_ok=True)
        self.share_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class ClientConfig:
    """客户端运行参数。"""

    host: str = field(default_factory=lambda: _env(ENV_HOST, "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env(ENV_PORT, "5001")))
    password: str = field(default_factory=lambda: _env(ENV_PASSWORD, DEMO_PASSWORD))
    data_dir: Path = field(
        default_factory=lambda: Path(_env(ENV_DATA_DIR, ".")).resolve()
    )
    chunk_size: int = CHUNK_SIZE

    @property
    def using_demo_password(self) -> bool:
        return self.password == DEMO_PASSWORD

    @property
    def download_dir(self) -> Path:
        return self.data_dir / CLIENT_DOWN_DIR_NAME

    def ensure_dirs(self) -> None:
        self.download_dir.mkdir(parents=True, exist_ok=True)
