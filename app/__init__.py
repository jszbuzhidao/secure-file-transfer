"""局域网加密文件传输系统（完善版）。

分层结构：
    config          集中配置（密钥不落源码）
    crypto          纯函数加密层：AES-256-GCM / SHA-256 / PBKDF2 / HMAC      ← 可单测
    protocol        自定义 TLV 二进制协议编解码，解决 TCP 粘包/半包            ← 可单测
    resume_store    接收端断点续传存储（.part + 元数据）                      ← 可单测
    transfer        分块传输调度（发送端 / 接收端）                            ← 可单测
    server_core     服务端会话逻辑（认证 + 上传 + 下发）
    client_core     客户端会话逻辑（认证 + 上传 + 下发）
    cli_server/cli_client   命令行入口（可在服务器上跑，便于容器化）
    gui_server/gui_client   tkinter 图形界面（保留原课设交互方式）
"""

__version__ = "2.0.0"
