"""protocol 层单元测试：帧编解码、粘包/半包、魔数/版本校验、定长读取。

重点验证 recv_exact 解决 TCP 粘包/半包的核心价值，以及脏数据被协议层尽早拒掉。
"""

from __future__ import annotations

import json
import struct
import threading

import pytest

from app import config, protocol

# 发送线程辅助：可选逐字节发送，用于模拟半包
def _send_thread(sock, data: bytes, bytewise: bool = False) -> threading.Thread:
    def run() -> None:
        if bytewise:
            for i in range(len(data)):
                sock.sendall(data[i : i + 1])
        else:
            sock.sendall(data)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# 帧往返
# ---------------------------------------------------------------------------


def test_frame_roundtrip(loopback_pair) -> None:
    a, b = loopback_pair
    payload = b"hello world" * 3
    _send_thread(a, protocol.encode_frame(0x12, payload))
    frame = protocol.recv_frame(b)
    assert frame.type == 0x12
    assert frame.payload == payload


def test_zero_length_frame(loopback_pair) -> None:
    a, b = loopback_pair
    _send_thread(a, protocol.encode_frame(0x10, b""))
    frame = protocol.recv_frame(b)
    assert frame.type == 0x10
    assert frame.payload == b""


def test_encode_json_roundtrip(loopback_pair) -> None:
    a, b = loopback_pair
    obj = {"name": "x", "size": 10, "sha256": "abc"}
    _send_thread(a, protocol.encode_json(0x20, obj))
    frame = protocol.recv_frame(b)
    assert frame.type == 0x20
    assert protocol.parse_json(frame) == obj


# ---------------------------------------------------------------------------
# 帧头结构自洽
# ---------------------------------------------------------------------------


def test_header_is_12_bytes() -> None:
    assert protocol.HEADER_SIZE == 12
    assert struct.calcsize(protocol.HEADER_FORMAT) == 12
    assert protocol.HEADER_FORMAT == ">2sBBII"
    out = protocol.encode_frame(0x01, b"x" * 5)
    assert len(out) == 12 + 5


def test_message_type_constants_unique() -> None:
    vals = [
        v
        for k, v in vars(protocol.MessageType).items()
        if not k.startswith("_") and isinstance(v, int)
    ]
    assert len(vals) == len(set(vals))


# ---------------------------------------------------------------------------
# 粘包 / 半包（recv_exact 的核心价值）
# ---------------------------------------------------------------------------


def test_split_byte_send_reassembled(loopback_pair) -> None:
    a, b = loopback_pair
    payload = bytes(range(256)) * 4
    frame = protocol.encode_frame(0x12, payload)
    _send_thread(a, frame, bytewise=True)  # 逐字节发送，模拟极端半包
    got = protocol.recv_frame(b)
    assert got.type == 0x12
    assert got.payload == payload


def test_glued_frames_split_correctly(loopback_pair) -> None:
    a, b = loopback_pair
    frames = [
        protocol.encode_frame(0x10, b"aaa"),
        protocol.encode_frame(0x11, b"bbbbb"),
        protocol.encode_frame(0x12, b"cccccc"),
    ]
    _send_thread(a, b"".join(frames))  # 一次 sendall 连发三帧（粘包）
    g1 = protocol.recv_frame(b)
    g2 = protocol.recv_frame(b)
    g3 = protocol.recv_frame(b)
    assert (g1.type, g1.payload) == (0x10, b"aaa")
    assert (g2.type, g2.payload) == (0x11, b"bbbbb")
    assert (g3.type, g3.payload) == (0x12, b"cccccc")


def test_large_frame_roundtrip(loopback_pair) -> None:
    a, b = loopback_pair
    payload = bytes((i * 7 + 3) % 256 for i in range(1 << 20))  # 1 MiB
    _send_thread(a, protocol.encode_frame(0x12, payload))
    got = protocol.recv_frame(b)
    assert got.payload == payload


# ---------------------------------------------------------------------------
# 协议层拒绝脏数据
# ---------------------------------------------------------------------------


def test_magic_mismatch(loopback_pair) -> None:
    a, b = loopback_pair
    bad = struct.pack(">2sBBII", b"\x00\x00", config.PROTOCOL_VERSION, 0, 0, 0)
    _send_thread(a, bad)
    with pytest.raises(protocol.ProtocolError):
        protocol.recv_frame(b)


def test_version_mismatch(loopback_pair) -> None:
    a, b = loopback_pair
    bad = struct.pack(
        protocol.HEADER_FORMAT, config.MAGIC, 99, 0, 0, 0
    )
    _send_thread(a, bad)
    with pytest.raises(protocol.ProtocolError):
        protocol.recv_frame(b)


def test_payload_len_exceeds_max(loopback_pair) -> None:
    a, b = loopback_pair
    bad = struct.pack(
        protocol.HEADER_FORMAT,
        config.MAGIC,
        config.PROTOCOL_VERSION,
        0,
        0,
        protocol.MAX_PAYLOAD + 1,
    )
    _send_thread(a, bad)
    with pytest.raises(protocol.ProtocolError):
        protocol.recv_frame(b)


def test_encode_frame_rejects_oversize() -> None:
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_frame(0x01, b"x" * (protocol.MAX_PAYLOAD + 1))


def test_encode_frame_rejects_non_bytes() -> None:
    with pytest.raises(TypeError):
        protocol.encode_frame(0x01, "not-bytes")


# ---------------------------------------------------------------------------
# recv_exact
# ---------------------------------------------------------------------------


def test_recv_exact_zero_returns_empty(loopback_pair) -> None:
    _, b = loopback_pair
    assert protocol.recv_exact(b, 0) == b""


def test_recv_exact_negative_raises() -> None:
    with pytest.raises(protocol.ProtocolError):
        protocol.recv_exact(None, -1)


def test_recv_exact_peer_closes(loopback_pair) -> None:
    a, b = loopback_pair
    a.close()  # 对端提前关闭
    with pytest.raises(ConnectionResetError):
        protocol.recv_exact(b, 10)


# ---------------------------------------------------------------------------
# DATA 载荷打包
# ---------------------------------------------------------------------------


def test_data_payload_roundtrip() -> None:
    off = 12345
    ct = b"ciphertext-bytes"
    packed = protocol.pack_data_payload(off, ct)
    o, c = protocol.unpack_data_payload(packed)
    assert o == off and c == ct


def test_data_payload_too_short() -> None:
    with pytest.raises(protocol.ProtocolError):
        protocol.unpack_data_payload(b"\x00\x00")


def test_data_payload_negative_offset() -> None:
    with pytest.raises(protocol.ProtocolError):
        protocol.pack_data_payload(-1, b"x")


# ---------------------------------------------------------------------------
# parse_json
# ---------------------------------------------------------------------------


def test_parse_json_invalid_utf8() -> None:
    f = protocol.Frame(type=0x01, payload=b"\xff\xfe\x00")
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_json(f)


def test_parse_json_invalid_json() -> None:
    f = protocol.Frame(type=0x01, payload=b"{not valid json")
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_json(f)
