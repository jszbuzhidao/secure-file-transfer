"""加密层：全部是纯函数，不碰 socket、不碰界面，因此可以被 pytest 直接单测。

对照原版的三处升级：

| 项目       | 原版                        | 现在                                  |
|------------|-----------------------------|---------------------------------------|
| 对称加密   | AES-128-CBC + PKCS7 填充     | **AES-256-GCM**（32 字节密钥 + 认证标签）|
| 完整性校验 | MD5                         | **SHA-256**                           |
| 密钥来源   | 硬编码 `b'1234567890abcdef'` | **PBKDF2-HMAC-SHA256**(200k 迭代 + 随机盐) |
| 身份验证   | 口令明文过网                 | **HMAC-SHA256 挑战应答**（口令从不过网） |

CBC 只提供保密性，不做完整性校验 → 存在 padding oracle / 篡改不可知的问题；
GCM 是 AEAD 认证加密，密文被改一个 bit，解密时直接抛错，这是"加密 + 完整性"一次性解决。
"""

from __future__ import annotations

import hashlib
import hmac
import os

from Crypto.Cipher import AES

from . import config

# ---------------------------------------------------------------------------
# 密钥派生
# ---------------------------------------------------------------------------


def generate_salt(size: int = config.SALT_BYTES) -> bytes:
    """生成密码学安全随机盐（每次会话不同，抵御彩虹表）。"""
    return os.urandom(size)


def derive_master_key(
    password: str, salt: bytes, iterations: int = config.PBKDF2_ITERATIONS
) -> bytes:
    """由口令 + 盐派生出 32 字节主密钥。

    使用 PBKDF2-HMAC-SHA256，迭代 20 万次，让暴力枚举的代价提高数个数量级。
    """
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt 必须是 bytes")
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes(salt), iterations, dklen=config.KEY_BYTES
    )


def derive_subkeys(master_key: bytes) -> tuple[bytes, bytes]:
    """从主密钥分离出「加密子密钥」和「认证子密钥」。

    密钥分离（key separation）是好习惯：加密和 MAC 使用同一把密钥会削弱安全性。
    这里用一个固定标签 + HKDF 的简化实现（HMAC 作为 PRF）。
    """
    if len(master_key) != config.KEY_BYTES:
        raise ValueError("主密钥必须是 32 字节")

    def _prf(label: bytes) -> bytes:
        return hmac.new(master_key, label, hashlib.sha256).digest()

    return _prf(b"secure-file-transfer/enc"), _prf(b"secure-file-transfer/mac")


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM 加密。

    输出格式：``nonce(12) || tag(16) || ciphertext``
    ``aad``（附加认证数据）不加密但参与认证，用来把「这段密文属于哪个文件哪一段」
    绑死，防止攻击者把 A 文件的密文块搬到 B 文件里重放。
    """
    if len(key) != config.KEY_BYTES:
        raise ValueError(f"AES-256 需要 {config.KEY_BYTES} 字节密钥，收到 {len(key)}")
    nonce = os.urandom(config.NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=config.TAG_BYTES)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM 解密；密文或 AAD 被篡改会抛 ``ValueError``。"""
    if len(key) != config.KEY_BYTES:
        raise ValueError(f"AES-256 需要 {config.KEY_BYTES} 字节密钥，收到 {len(key)}")
    overhead = config.NONCE_BYTES + config.TAG_BYTES
    if len(blob) < overhead:
        raise ValueError("密文长度不足，数据损坏")
    nonce = blob[: config.NONCE_BYTES]
    tag = blob[config.NONCE_BYTES : overhead]
    ciphertext = blob[overhead:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=config.TAG_BYTES)
    if aad:
        cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:  # MAC 校验失败
        raise ValueError("GCM 认证失败：数据被篡改或密钥不匹配") from exc


def chunk_aad(file_id: str, offset: int) -> bytes:
    """构造分块的 AAD：把 file_id 与偏移量绑进认证标签。"""
    return f"{file_id}:{offset}".encode("utf-8")


# ---------------------------------------------------------------------------
# SHA-256 完整性校验
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path, chunk_size: int = config.CHUNK_SIZE) -> str:
    """流式计算整文件 SHA-256，内存占用与文件大小无关。"""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# HMAC 挑战应答
# ---------------------------------------------------------------------------


def hmac_sign(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_verify(key: bytes, message: bytes, signature: bytes) -> bool:
    """常数时间比较，避免计时侧信道。"""
    return hmac.compare_digest(hmac_sign(key, message), signature)


def build_auth_response(master_key: bytes, server_nonce: bytes) -> bytes:
    """客户端应答：HMAC(主密钥, 服务端随机数)。口令本身从不上网。"""
    return hmac_sign(master_key, b"auth:" + server_nonce)
