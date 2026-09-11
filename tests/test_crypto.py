"""crypto 层单元测试：AES-256-GCM、PBKDF2、SHA-256、HMAC 挑战应答。

目标：证明"真正的 AES-256 / SHA-256 / 认证加密 + 篡改检测 / 密钥分离 / 挑战应答"，
而不仅仅是接口存在。
"""

from __future__ import annotations

import hashlib
import os

import pytest

from app import config, crypto


# ---------------------------------------------------------------------------
# AES-256-GCM 往返 + 篡改检测 + AAD 绑定
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pt_len", [0, 1, config.CHUNK_SIZE, 123457])
def test_gcm_roundtrip(key: bytes, pt_len: int) -> None:
    pt = bytes((i * 7 + 3) % 256 for i in range(pt_len))
    blob = crypto.aes_gcm_encrypt(key, pt)
    assert crypto.aes_gcm_decrypt(key, blob) == pt


def test_gcm_tamper_ciphertext(key: bytes) -> None:
    pt = b"secret payload"
    blob = bytearray(crypto.aes_gcm_encrypt(key, pt))
    # 翻转密文区的 1 个 bit（密文从 overhead 之后开始）
    overhead = config.NONCE_BYTES + config.TAG_BYTES
    blob[overhead] ^= 0x01
    with pytest.raises(ValueError):
        crypto.aes_gcm_decrypt(key, bytes(blob))


def test_gcm_tamper_tag(key: bytes) -> None:
    blob = bytearray(crypto.aes_gcm_encrypt(key, b"data"))
    # 翻转 tag 区的 1 个 bit
    blob[config.NONCE_BYTES] ^= 0x80
    with pytest.raises(ValueError):
        crypto.aes_gcm_decrypt(key, bytes(blob))


def test_gcm_truncated(key: bytes) -> None:
    blob = crypto.aes_gcm_encrypt(key, b"hello world")
    # 截断到 overhead 以上但破坏密文/tag
    with pytest.raises(ValueError):
        crypto.aes_gcm_decrypt(key, blob[:-1])


def test_gcm_wrong_aad(key: bytes) -> None:
    pt = b"same plaintext"
    blob = crypto.aes_gcm_encrypt(key, pt, aad=crypto.chunk_aad("fileA", 0))
    # 不同 file_id -> AAD 不匹配
    with pytest.raises(ValueError):
        crypto.aes_gcm_decrypt(key, blob, aad=crypto.chunk_aad("fileB", 0))
    # 不同 offset -> AAD 不匹配（防止跨块搬移重放）
    with pytest.raises(ValueError):
        crypto.aes_gcm_decrypt(key, blob, aad=crypto.chunk_aad("fileA", 4096))


def test_gcm_wrong_key(key: bytes) -> None:
    blob = crypto.aes_gcm_encrypt(key, b"data")
    other = crypto.generate_salt(config.KEY_BYTES)
    with pytest.raises(ValueError):
        crypto.aes_gcm_decrypt(other, blob)


def test_gcm_rejects_128bit_key(key: bytes) -> None:
    # 证明现在真的是 AES-256（32 字节），16 字节密钥必须被拒绝
    with pytest.raises(ValueError):
        crypto.aes_gcm_encrypt(b"x" * 16, b"data")
    with pytest.raises(ValueError):
        crypto.aes_gcm_decrypt(b"x" * 16, crypto.aes_gcm_encrypt(key, b"data"))


# ---------------------------------------------------------------------------
# 密钥派生
# ---------------------------------------------------------------------------


def test_derive_master_key_deterministic() -> None:
    pw = "password"
    salt = crypto.generate_salt()
    assert crypto.derive_master_key(pw, salt) == crypto.derive_master_key(pw, salt)
    assert len(crypto.derive_master_key(pw, salt)) == config.KEY_BYTES


def test_derive_master_key_salt_matters() -> None:
    pw = "password"
    k1 = crypto.derive_master_key(pw, crypto.generate_salt())
    k2 = crypto.derive_master_key(pw, crypto.generate_salt())
    assert k1 != k2


def test_derive_subkeys_distinct_and_separated() -> None:
    master = crypto.generate_salt(config.KEY_BYTES)
    ek, mk = crypto.derive_subkeys(master)
    assert ek != mk
    assert len(ek) == config.KEY_BYTES
    assert len(mk) == config.KEY_BYTES
    # 主密钥长度不对应被拒绝
    with pytest.raises(ValueError):
        crypto.derive_subkeys(b"short")


# ---------------------------------------------------------------------------
# SHA-256
# ---------------------------------------------------------------------------


def test_sha256_bytes_known_vector() -> None:
    assert (
        crypto.sha256_bytes(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_file_matches_hashlib(tmp_path) -> None:
    data = bytes((i * 7 + 3) % 256 for i in range(500_000))
    p = tmp_path / "big.bin"
    p.write_bytes(data)
    assert crypto.sha256_file(p) == hashlib.sha256(data).hexdigest()


def test_sha256_file_chunk_size_invariant(tmp_path) -> None:
    data = bytes((i * 5 + 1) % 256 for i in range(500_000))
    p = tmp_path / "big.bin"
    p.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert crypto.sha256_file(p, config.CHUNK_SIZE) == expected
    assert crypto.sha256_file(p, 1) == expected  # 1 字节分块读，结果一致


# ---------------------------------------------------------------------------
# HMAC 挑战应答
# ---------------------------------------------------------------------------


def test_hmac_verify_basic(key: bytes) -> None:
    msg = b"auth:" + os.urandom(32)
    sig = crypto.hmac_sign(key, msg)
    assert crypto.hmac_verify(key, msg, sig) is True


def test_hmac_verify_tamper_and_length(key: bytes) -> None:
    msg = b"auth:" + os.urandom(32)
    sig = crypto.hmac_sign(key, msg)
    assert crypto.hmac_verify(key, msg, sig[:-1]) is False  # 长度不符
    assert crypto.hmac_verify(key, msg, bytes(config.KEY_BYTES)) is False  # 错误签名
    assert crypto.hmac_verify(key, msg + b"x", sig) is False  # 消息被篡改


def test_build_auth_response_matches_server_check() -> None:
    # 服务端校验逻辑：hmac_verify(master, b"auth:"+nonce, resp)
    master = crypto.generate_salt(config.KEY_BYTES)
    nonce = os.urandom(32)
    resp = crypto.build_auth_response(master, nonce)
    assert crypto.hmac_verify(master, b"auth:" + nonce, resp) is True
    assert crypto.hmac_verify(master, b"auth:" + nonce + b"x", resp) is False
