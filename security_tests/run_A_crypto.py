"""Red-team A: 加密层篡改检测 + AES-256 真正确认。
统计实际执行的篡改测试次数与被正确拒绝的次数。
"""
import sys, traceback
sys.path.insert(0, ".")
from app import config, crypto

key = crypto.generate_salt(config.KEY_BYTES)
rejected = 0
total = 0
fails = []

def check(name, fn):
    global total, rejected
    total += 1
    try:
        fn()
        # fn 应当抛异常；没抛 = 没拒绝 = 失败
        fails.append(f"[未拒绝] {name}")
    except ValueError as e:
        rejected += 1
        print(f"[OK 拒绝] {name}: {e}")
    except Exception as e:
        fails.append(f"[异常类型不符] {name}: {type(e).__name__}: {e}")

blob0 = crypto.aes_gcm_encrypt(key, b"secret payload data here")
overhead = config.NONCE_BYTES + config.TAG_BYTES

# 1. 篡改密文任意 1 bit
def t1():
    b = bytearray(blob0)
    b[overhead] ^= 0x01
    crypto.aes_gcm_decrypt(key, bytes(b))
check("篡改密文1bit", t1)

# 2. 篡改 GCM tag
def t2():
    b = bytearray(blob0)
    b[config.NONCE_BYTES] ^= 0x80
    crypto.aes_gcm_decrypt(key, bytes(b))
check("篡改GCM tag", t2)

# 3. 截断密文
def t3():
    crypto.aes_gcm_decrypt(key, blob0[:-1])
check("截断密文", t3)

# 4. 交换两个分块的密文（AAD 防重放）：把块A的密文用块B的offset去解
def t4():
    aadA = crypto.chunk_aad("file", 0)
    aadB = crypto.chunk_aad("file", 65536)
    ctA = crypto.aes_gcm_encrypt(key, b"A"*100, aadA)
    # 攻击者把 ctA 当作 offset=65536 的块发过去
    crypto.aes_gcm_decrypt(key, ctA, aadB)
check("交换分块(AAD绑定offset)", t4)

# 5. 错误密钥
def t5():
    other = crypto.generate_salt(config.KEY_BYTES)
    crypto.aes_gcm_decrypt(other, blob0)
check("错误密钥", t5)

# 6. 16字节密钥调用 encrypt（证明是AES-256而非128）
def t6():
    crypto.aes_gcm_encrypt(b"x"*16, b"data")
check("16字节密钥必须被拒(AES-256)", t6)

# 7. 16字节密钥调用 decrypt
def t7():
    crypto.aes_gcm_decrypt(b"x"*16, blob0)
check("16字节密钥decrypt必须被拒", t7)

# 8. 空密文(长度不足)
def t8():
    crypto.aes_gcm_decrypt(key, b"short")
check("密文不足overhead", t8)

print(f"\n=== A 总结: 篡改/错误测试 {total} 次, 正确拒绝 {rejected} 次, 漏拒 {len(fails)} ===")
for f in fails:
    print("  ", f)
sys.exit(1 if fails else 0)
