"""自定义二进制协议层：帧编解码 + 消息类型定义。

原版的协议是「1 字节指令 + 若干个 4 字节长度头 + 裸数据」，问题在于：

1. 没有魔数（magic），收到脏数据无法识别，只能靠长度硬啃；
2. 没有版本号，将来协议升级无法兼容；
3. 没有序号（seq），请求/响应无法配对，双向同时传输时会串线；
4. 长度头用 4 字节，理论上单包上限 4 GiB，但一旦算出脏长度就会一直 recv 下去（DoS 风险）。

新协议统一为定长头 + 变长体：

    ┌────────┬───────┬──────┬──────────┬─────────────────┐
    │ MAGIC  │  VER  │ TYPE │  SEQ     │  PAYLOAD_LEN    │
    │ 2 字节  │ 1 字节 │1 字节│  4 字节   │     4 字节       │
    └────────┴───────┴──────┴──────────┴─────────────────┘
    └───────────── 12 字节定长头 ─────────────┘

``recv_frame`` 内部用 ``recv_exact`` 循环读满，TCP 粘包/半包问题在协议层一次性解决，
上层业务代码不再需要关心 ``recv`` 返回了多少字节。
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any

from . import config

# 帧头格式：magic(2s) version(B) type(B) seq(I) payload_len(I) = 12 字节
HEADER_FORMAT = ">2sBBII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_PAYLOAD = 16 * 1024 * 1024  # 单帧上限 16 MiB，防止脏长度导致无限 recv

assert HEADER_SIZE == 12, f"帧头必须是 12 字节，当前 {HEADER_SIZE}"


class MessageType:
    """消息类型常量。0x0x 为认证阶段，0x1x 为上传，0x2x 为下载，0xFx 为控制。"""

    HELLO = 0x01          # C→S 请求握手
    CHALLENGE = 0x02      # S→C 下发盐 + 随机挑战数
    AUTH = 0x03           # C→S HMAC 应答
    AUTH_OK = 0x04        # S→C 认证通过
    AUTH_FAIL = 0x05      # S→C 认证失败

    PUT_BEGIN = 0x10      # C→S 声明要上传
    PUT_RESUME = 0x11     # S→C 告知已收到的偏移量（断点续传核心）
    DATA = 0x12           # 双向：加密分块
    PUT_END = 0x13        # C→S 上传结束
    PUT_ACK = 0x14        # S→C 上传结果

    GET_BEGIN = 0x20      # C→S 请求下发某个文件
    GET_INFO = 0x21       # S→C 文件元信息（权威 file_id / size / sha256）
    GET_END = 0x22        # S→C 下发结束
    GET_ACK = 0x23        # C→S 接收结果
    GET_RESUME = 0x24     # C→S 告知本地已有偏移，服务端从这里开始发

    ERROR = 0xEE          # 双向：错误
    BYE = 0xFF            # 双向：正常关闭


class ProtocolError(Exception):
    """协议层错误：魔数不匹配、版本不符、长度非法等。"""


@dataclass
class Frame:
    type: int
    payload: bytes = b""
    seq: int = 0

    @property
    def length(self) -> int:
        return len(self.payload)


def encode_frame(msg_type: int, payload: bytes = b"", seq: int = 0) -> bytes:
    """把一条消息编码成完整帧（头 + 体）。"""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload 必须是 bytes")
    body = bytes(payload)
    if len(body) > MAX_PAYLOAD:
        raise ProtocolError(f"单帧载荷超限：{len(body)} > {MAX_PAYLOAD}")
    header = struct.pack(
        HEADER_FORMAT, config.MAGIC, config.PROTOCOL_VERSION, msg_type, seq, len(body)
    )
    return header + body


def encode_json(msg_type: int, obj: Any, seq: int = 0) -> bytes:
    """把 dict 序列化成 JSON 再装帧（UTF-8）。"""
    payload = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return encode_frame(msg_type, payload, seq)


# ---------------------------------------------------------------------------
# 底层：定长读取 / 定长发送
# ---------------------------------------------------------------------------


def recv_exact(sock, length: int) -> bytes:
    """精确读满 ``length`` 字节。

    这是解决 TCP 粘包/半包的关键原语：``sock.recv(n)`` 只保证"最多 n 字节"，
    必须循环累积直到读满。原版已经有这个函数，保留并加了长度校验。
    """
    if length < 0:
        raise ProtocolError(f"非法的读取长度：{length}")
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(min(length - len(buf), 64 * 1024))
        if not chunk:
            raise ConnectionResetError("对端连接已断开")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock) -> Frame:
    """从 socket 读出一个完整帧。"""
    header = recv_exact(sock, HEADER_SIZE)
    magic, version, msg_type, seq, payload_len = struct.unpack(HEADER_FORMAT, header)

    if magic != config.MAGIC:
        raise ProtocolError(f"帧魔数不匹配：{magic!r}，流已错位")
    if version != config.PROTOCOL_VERSION:
        raise ProtocolError(f"协议版本不支持：{version} != {config.PROTOCOL_VERSION}")
    if payload_len > MAX_PAYLOAD:
        raise ProtocolError(f"帧长度非法：{payload_len}")

    payload = recv_exact(sock, payload_len) if payload_len else b""
    return Frame(type=msg_type, payload=payload, seq=seq)


def send_frame(sock, msg_type: int, payload: bytes = b"", seq: int = 0) -> None:
    """发送一个完整帧（``sendall`` 保证全部写出）。"""
    sock.sendall(encode_frame(msg_type, payload, seq))


def send_json(sock, msg_type: int, obj: Any, seq: int = 0) -> None:
    sock.sendall(encode_json(msg_type, obj, seq))


def parse_json(frame: Frame) -> Any:
    """把帧载荷当 JSON 解析。"""
    try:
        return json.loads(frame.payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"JSON 载荷解析失败：{exc}") from exc


# ---------------------------------------------------------------------------
# DATA 帧载荷：offset(8) || ciphertext
# ---------------------------------------------------------------------------

DATA_OFFSET_FORMAT = ">Q"  # 8 字节无符号大端
DATA_OFFSET_SIZE = struct.calcsize(DATA_OFFSET_FORMAT)


def pack_data_payload(offset: int, ciphertext: bytes) -> bytes:
    """打包一个数据块：8 字节明文偏移 + GCM 密文。

    偏移量明文传输（不是秘密），但会被写进 GCM 的 AAD 参与认证，
    因此攻击者改偏移量会导致解密失败。
    """
    if offset < 0:
        raise ProtocolError("偏移量不能为负")
    return struct.pack(DATA_OFFSET_FORMAT, offset) + ciphertext


def unpack_data_payload(payload: bytes) -> tuple[int, bytes]:
    """解包数据块，返回 ``(offset, ciphertext)``。"""
    if len(payload) < DATA_OFFSET_SIZE:
        raise ProtocolError("DATA 帧载荷过短，缺少偏移量")
    offset = struct.unpack(DATA_OFFSET_FORMAT, payload[:DATA_OFFSET_SIZE])[0]
    return offset, payload[DATA_OFFSET_SIZE:]
