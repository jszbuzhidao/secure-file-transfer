"""会话层：认证握手 + 上传/下发四个会话过程。

服务端和客户端共用这一层的逻辑，只是"谁主动"不同：

    ┌──────────┬───────────────────────┬───────────────────────┐
    │ 过程     │ 主动方                │ 入口函数              │
    ├──────────┼───────────────────────┼───────────────────────┤
    │ 认证     │ 客户端                │ client_handshake      │
    │          │ 服务端                │ server_handshake      │
    │ 上传     │ 客户端                │ request_upload        │
    │          │ 服务端                │ handle_upload         │
    │ 下发     │ 客户端发起请求        │ request_download      │
    │          │ 服务端响应            │ handle_download       │
    └──────────┴───────────────────────┴───────────────────────┘

认证设计（对比原版"口令明文过网"）：
  1. 客户端发 HELLO；
  2. 服务端回 CHALLENGE（随机盐 + 随机挑战数，每次连接都不同）；
  3. 客户端用 PBKDF2(口令, 盐) 派生主密钥，回 HMAC(主密钥, 挑战数)；
  4. 服务端本地算一遍比对。**口令全程不上网**，抓包只能拿到随机数和一个 HMAC 值，
     且每次都不同，无法重放。
"""

from __future__ import annotations

import os
from pathlib import Path

from . import config, crypto, protocol, resume_store, transfer
from .protocol import MessageType, ProtocolError
from .resume_store import ResumeStore
from .transfer import FileInfo, TransferError

# 挑战数长度
CHALLENGE_BYTES = 32


class AuthError(Exception):
    """认证失败。"""


class SessionError(Exception):
    """会话层业务错误。"""


def _safe_basename(name: str) -> str:
    """防目录穿越：只取文件名，拒绝 ``../`` 之类的路径。"""
    base = os.path.basename(str(name).replace("\\", "/"))
    if not base or base in {".", ".."}:
        raise SessionError(f"非法文件名：{name!r}")
    return base


def send_error(sock, message: str) -> None:
    """统一的错误应答帧。"""
    protocol.send_json(sock, MessageType.ERROR, {"message": message})


def next_request_frame(conn) -> protocol.Frame:
    """服务端多路复用：读取下一个请求帧（PUT_BEGIN / GET_BEGIN / BYE）。

    上行和下行都是由客户端发起的，所以服务端只维护一条长连接，
    读到一个帧后按类型分派给 ``handle_upload`` 或 ``handle_download``。
    """
    return protocol.recv_frame(conn)


# ---------------------------------------------------------------------------
# 1. 认证握手
# ---------------------------------------------------------------------------


def server_handshake(conn, password: str, iterations: int = config.PBKDF2_ITERATIONS):
    """服务端握手。成功返回 ``(enc_key, mac_key)``，失败抛 ``AuthError``。"""
    frame = protocol.recv_frame(conn)
    if frame.type != MessageType.HELLO:
        raise AuthError(f"握手首帧类型错误：0x{frame.type:02x}")

    salt = crypto.generate_salt()
    nonce = os.urandom(CHALLENGE_BYTES)
    protocol.send_json(
        conn,
        MessageType.CHALLENGE,
        {
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "iterations": iterations,
            "version": config.PROTOCOL_VERSION,
        },
    )

    frame = protocol.recv_frame(conn)
    if frame.type != MessageType.AUTH:
        protocol.send_json(conn, MessageType.AUTH_FAIL, {"reason": "unexpected_frame"})
        raise AuthError("客户端未按协议提交认证应答")

    master = crypto.derive_master_key(password, salt, iterations)
    if not crypto.hmac_verify(master, b"auth:" + nonce, frame.payload):
        protocol.send_json(conn, MessageType.AUTH_FAIL, {"reason": "bad_credential"})
        raise AuthError("口令校验失败")

    enc_key, mac_key = crypto.derive_subkeys(master)
    protocol.send_json(
        conn, MessageType.AUTH_OK, {"version": config.PROTOCOL_VERSION, "cipher": "AES-256-GCM"}
    )
    return enc_key, mac_key


def client_handshake(sock, password: str):
    """客户端握手。成功返回 ``(enc_key, mac_key)``，失败抛 ``AuthError``。"""
    protocol.send_json(
        sock, MessageType.HELLO, {"version": config.PROTOCOL_VERSION, "agent": "sft-client"}
    )
    frame = protocol.recv_frame(sock)
    if frame.type != MessageType.CHALLENGE:
        raise AuthError(f"期望 CHALLENGE，收到 0x{frame.type:02x}")

    challenge = protocol.parse_json(frame)
    salt = bytes.fromhex(challenge["salt"])
    nonce = bytes.fromhex(challenge["nonce"])
    iterations = int(challenge.get("iterations", config.PBKDF2_ITERATIONS))

    master = crypto.derive_master_key(password, salt, iterations)
    protocol.send_frame(
        sock, MessageType.AUTH, crypto.build_auth_response(master, nonce)
    )

    frame = protocol.recv_frame(sock)
    if frame.type == MessageType.AUTH_FAIL:
        reason = protocol.parse_json(frame).get("reason", "unknown")
        raise AuthError(f"服务端拒绝认证：{reason}")
    if frame.type != MessageType.AUTH_OK:
        raise AuthError(f"期望 AUTH_OK，收到 0x{frame.type:02x}")

    return crypto.derive_subkeys(master)


# ---------------------------------------------------------------------------
# 2. 上传（客户端 → 服务端）
# ---------------------------------------------------------------------------


def request_upload(sock, enc_key: bytes, path, progress=None) -> dict:
    """客户端上传一个文件，返回服务端回执 dict。

    支持断点续传：先声明 ``PUT_BEGIN``，服务端回 ``PUT_RESUME`` 告知已有偏移，
    客户端从该偏移开始发，不重传已经落盘的部分。
    """
    info = transfer.inspect_file(path)
    protocol.send_json(sock, MessageType.PUT_BEGIN, info.to_dict())

    frame = protocol.recv_frame(sock)
    if frame.type == MessageType.ERROR:
        raise TransferError(protocol.parse_json(frame).get("message", "服务端拒绝上传"))
    if frame.type != MessageType.PUT_RESUME:
        raise ProtocolError(f"期望 PUT_RESUME，收到 0x{frame.type:02x}")

    start = int(protocol.parse_json(frame).get("offset", 0))
    start = max(0, min(start, info.size))

    transfer.send_file(sock, enc_key, path, info, start_offset=start, progress=progress)
    protocol.send_json(
        sock, MessageType.PUT_END, {"file_id": info.file_id, "sha256": info.sha256}
    )

    frame = protocol.recv_frame(sock)
    if frame.type != MessageType.PUT_ACK:
        raise ProtocolError(f"期望 PUT_ACK，收到 0x{frame.type:02x}")
    result = protocol.parse_json(frame)
    result.setdefault("resumed_from", start)
    return result


def handle_upload(conn, enc_key: bytes, recv_dir, progress=None, first_frame=None) -> dict:
    """服务端处理一次上传：协商续传偏移 → 收块 → 校验 → 回 ``PUT_ACK``。

    返回回执 dict（与发给客户端的 ``PUT_ACK`` 载荷一致）。

    注意：本函数**自己负责发送应答帧**，与 ``request_upload`` 的接收侧严格对称，
    避免上层忘记回包导致客户端一直挂等（这是原版最容易踩的坑）。

    ``first_frame``：若上层多路复用已读过 ``PUT_BEGIN``，可传入避免重复读取。
    """
    frame = first_frame if first_frame is not None else protocol.recv_frame(conn)
    if frame.type != MessageType.PUT_BEGIN:
        raise ProtocolError(f"期望 PUT_BEGIN，收到 0x{frame.type:02x}")

    info = FileInfo.from_dict(protocol.parse_json(frame))
    info.name = _safe_basename(info.name)

    # 串行化「同一目标文件的整个上传会话」，原因见 resume_store.target_lock 的注释：
    # Windows 下 os.replace 要求源文件无其它句柄，并发同目标会集体 PermissionError。
    # 排在后面的会话拿到锁后会发现成品已就位，走下面的幂等短路零流量成功。
    with resume_store.target_lock(recv_dir, info.name):
        # ---- 幂等短路：目标文件已存在且内容一致 ⇒ 一个字节都不用传 --------------
        # file_id 是内容 SHA-256，所以「同名 + 同大小 + 同 SHA-256」等价于内容已就位。
        if _already_present(recv_dir, info):
            protocol.send_json(
                conn,
                MessageType.PUT_RESUME,
                {"offset": info.size, "file_id": info.file_id, "resumed": False},
            )
            # 客户端在 offset==size 时不会发任何 DATA，只会补一个 PUT_END，先收掉它，
            # 保持与正常路径的帧序完全一致（协议对称，少一个分支少一个坑）。
            protocol.recv_frame(conn)
            result = {
                "ok": True,
                "file_id": info.file_id,
                "name": info.name,
                "resumed_from": info.size,
                "size": info.size,
                "sha256": info.sha256,
                "saved_as": str(Path(recv_dir) / info.name),
                "skipped": True,
                "message": "目标文件已存在且内容一致（内容寻址幂等），跳过传输",
            }
            protocol.send_json(conn, MessageType.PUT_ACK, result)
            return result

        store = transfer.make_store(recv_dir, info)
        resumed_from = store.next_offset
        protocol.send_json(
            conn,
            MessageType.PUT_RESUME,
            {
                "offset": resumed_from,
                "file_id": info.file_id,
                "resumed": resumed_from > 0,
            },
        )

        transfer.receive_file(
            conn, enc_key, store, end_types=(MessageType.PUT_END,), progress=progress
        )

        try:
            if not store.is_complete:
                store.abort()
                missing = sum(end - start for start, end in store.missing_ranges())
                # 说清楚"没有断点可续"还是"已保留断点"——一个字节都没收到时
                # `.part` 根本没被创建，说"已保留断点"是错的。
                tail = (
                    "（未收到任何数据，无断点可续，请重传）"
                    if store.next_offset == 0
                    else "，已保留断点可续传"
                )
                result = {
                    "ok": False,
                    "file_id": info.file_id,
                    "name": info.name,
                    "resumed_from": resumed_from,
                    "received_bytes": store.next_offset,
                    "missing_bytes": missing,
                    "message": f"数据不完整，缺 {missing} 字节{tail}",
                }
            else:
                final_path, actual_sha, ok = store.finish(verify=True)
                result = {
                    "ok": ok,
                    "file_id": info.file_id,
                    "name": info.name,
                    "resumed_from": resumed_from,
                    "size": info.size,
                    "sha256": actual_sha,
                    "saved_as": str(final_path),
                    "message": "校验通过，传输完成"
                    if ok
                    else "SHA-256 校验失败，文件可能被篡改",
                }
        except Exception as exc:  # noqa: BLE001 - 收尾失败必须回执，不能让客户端干等
            # 数据已经收完，只是落盘/清理环节出问题。此时**必须**把结果告诉客户端，
            # 否则客户端会一直阻塞在等 PUT_ACK，最后报出一个和真实原因无关的
            # "对端连接已断开"，排查成本极高。
            store.abort()
            # 兜底：并发/重命名竞争下可能别人已经把内容正确落盘了，结果等价于成功。
            if _already_present(recv_dir, info):
                result = {
                    "ok": True,
                    "file_id": info.file_id,
                    "name": info.name,
                    "resumed_from": resumed_from,
                    "size": info.size,
                    "sha256": info.sha256,
                    "saved_as": str(Path(recv_dir) / info.name),
                    "skipped": True,
                    "message": "同一内容已由并发会话落盘完成（内容寻址幂等），本次视为成功",
                }
            else:
                result = {
                    "ok": False,
                    "file_id": info.file_id,
                    "name": info.name,
                    "resumed_from": resumed_from,
                    "size": info.size,
                    "message": f"数据已收到但落盘收尾失败（{type(exc).__name__}: {exc}），"
                    f"断点文件已保留，可重试续传",
                }

        protocol.send_json(conn, MessageType.PUT_ACK, result)
        return result


def _already_present(recv_dir, info: FileInfo) -> bool:
    """目标目录里是否已有**内容完全一致**的成品文件。"""
    target = Path(recv_dir) / info.name
    try:
        if not target.is_file() or target.stat().st_size != info.size:
            return False
        return crypto.sha256_file(target) == info.sha256
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 3. 下发（服务端 → 客户端）
# ---------------------------------------------------------------------------


def request_download(sock, enc_key: bytes, name: str, dest_dir, progress=None) -> dict:
    """客户端请求下发文件，自动续传本地已有进度。"""
    protocol.send_json(sock, MessageType.GET_BEGIN, {"name": _safe_basename(name)})

    frame = protocol.recv_frame(sock)
    if frame.type == MessageType.ERROR:
        raise TransferError(protocol.parse_json(frame).get("message", "服务端无此文件"))
    if frame.type != MessageType.GET_INFO:
        raise ProtocolError(f"期望 GET_INFO，收到 0x{frame.type:02x}")

    info = FileInfo.from_dict(protocol.parse_json(frame))
    store = transfer.make_store(dest_dir, info)
    resumed_from = store.next_offset

    protocol.send_json(sock, MessageType.GET_RESUME, {"offset": resumed_from, "file_id": info.file_id})

    transfer.receive_file(
        sock,
        enc_key,
        store,
        end_types=(MessageType.GET_END,),
        progress=progress,
        start_offset=resumed_from,
    )

    ok = False
    saved_as = None
    actual_sha = ""
    if store.is_complete:
        try:
            final_path, actual_sha, ok = store.finish(verify=True)
            saved_as = str(final_path)
        except Exception as exc:  # noqa: BLE001 - 收尾失败也要回 GET_ACK，见 handle_upload 同处说明
            store.abort()
            ok = False
            actual_sha = ""
            protocol.send_json(
                sock,
                MessageType.GET_ACK,
                {
                    "ok": False,
                    "file_id": info.file_id,
                    "message": f"数据已收到但落盘收尾失败（{type(exc).__name__}: {exc}）",
                },
            )
            return {
                "ok": False,
                "file_id": info.file_id,
                "name": info.name,
                "size": info.size,
                "resumed_from": resumed_from,
                "message": f"数据已收到但落盘收尾失败：{exc}",
            }
    else:
        store.abort()
        tail = (
            "（未收到任何数据，无断点可续）"
            if store.next_offset == 0
            else "，已保留断点可续传"
        )
        protocol.send_json(
            sock,
            MessageType.GET_ACK,
            {"ok": False, "file_id": info.file_id, "message": f"数据不完整{tail}"},
        )
        return {
            "ok": False,
            "file_id": info.file_id,
            "name": info.name,
            "message": f"数据不完整{tail}",
        }

    protocol.send_json(
        sock,
        MessageType.GET_ACK,
        {
            "ok": ok,
            "file_id": info.file_id,
            "sha256": actual_sha,
            # 与 PUT_ACK 保持对称：无论成败都带 message，服务端日志才有可读的原因。
            "message": "校验通过，接收完成" if ok else "SHA-256 校验失败，文件可能被篡改",
        },
    )
    return {
        "ok": ok,
        "file_id": info.file_id,
        "name": info.name,
        "size": info.size,
        "sha256": actual_sha,
        "resumed_from": resumed_from,
        "saved_as": saved_as,
        "message": "校验通过，接收完成" if ok else "SHA-256 校验失败",
    }


def handle_download(conn, enc_key: bytes, share_dir, progress=None, first_frame=None) -> dict:
    """服务端响应一次下发请求。

    ``first_frame``：若上层多路复用已读过 ``GET_BEGIN``，可传入避免重复读取。
    """
    frame = first_frame if first_frame is not None else protocol.recv_frame(conn)
    if frame.type != MessageType.GET_BEGIN:
        raise ProtocolError(f"期望 GET_BEGIN，收到 0x{frame.type:02x}")

    req = protocol.parse_json(frame)
    try:
        name = _safe_basename(req.get("name", ""))
    except SessionError as exc:
        protocol.send_json(conn, MessageType.ERROR, {"message": str(exc)})
        return {"ok": False, "message": str(exc)}

    path = Path(share_dir) / name
    if not path.is_file():
        msg = f"服务端无此文件：{name}"
        protocol.send_json(conn, MessageType.ERROR, {"message": msg})
        return {"ok": False, "message": msg}

    info = transfer.inspect_file(path)
    protocol.send_json(conn, MessageType.GET_INFO, info.to_dict())

    frame = protocol.recv_frame(conn)
    if frame.type != MessageType.GET_RESUME:
        raise ProtocolError(f"期望 GET_RESUME，收到 0x{frame.type:02x}")
    start = int(protocol.parse_json(frame).get("offset", 0))
    start = max(0, min(start, info.size))

    sent = transfer.send_file(
        conn, enc_key, path, info, start_offset=start, progress=progress
    )
    protocol.send_json(
        conn,
        MessageType.GET_END,
        {"file_id": info.file_id, "sha256": info.sha256, "offset": start, "sent": sent},
    )

    frame = protocol.recv_frame(conn)
    if frame.type == MessageType.GET_ACK:
        ack = protocol.parse_json(frame)
    else:
        ack = {"ok": False, "message": "客户端未确认"}
    ack.setdefault("name", info.name)
    ack.setdefault("size", info.size)
    ack["resumed_from"] = start
    return ack
