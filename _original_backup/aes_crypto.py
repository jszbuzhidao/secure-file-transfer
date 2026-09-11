from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# AES-CBC 固定密钥，与两端统一
KEY = b'1234567890abcdef'
BLOCK_SIZE = AES.block_size

# CBC加密：返回 iv + 密文
def aes_cbc_encrypt(raw_data: bytes) -> bytes:
    # 生成16字节随机IV
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    padded = pad(raw_data, BLOCK_SIZE)
    cipher_text = cipher.encrypt(padded)
    # IV拼接在密文最前面，解密时拆分
    return iv + cipher_text

# CBC解密：传入iv+密文，还原原始二进制
def aes_cbc_decrypt(enc_data: bytes) -> bytes:
    # 前16字节为IV
    iv = enc_data[:BLOCK_SIZE]
    cipher_text = enc_data[BLOCK_SIZE:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    raw = cipher.decrypt(cipher_text)
    return unpad(raw, BLOCK_SIZE)