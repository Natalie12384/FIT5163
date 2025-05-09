import hashlib
import secrets
from ecdsa import SECP256k1, SigningKey, VerifyingKey

curve = SECP256k1
G = curve.generator
order = curve.order

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash_to_int(data: bytes) -> int:
    return int.from_bytes(sha256(data), 'big') % order

def generate_link_tag(public_key: VerifyingKey) -> bytes:
    """生成可链接标签（Linkability tag）"""
    return sha256(public_key.to_string())

def sign(message: str, private_key: SigningKey, ring: list[VerifyingKey]):
    """使用Linkable Ring Signature签名"""
    key_index = ring.index(private_key.get_verifying_key())
    n = len(ring)
    h = sha256(message.encode())

    # 随机数
    c = [0] * n
    s = [secrets.randbelow(order) for _ in range(n)]

    # 计算linkability tag
    tag = generate_link_tag(private_key.get_verifying_key())

    # 构造签名循环
    u = secrets.randbelow(order)
    temp = u * G
    c[(key_index + 1) % n] = hash_to_int(h + tag + temp.to_bytes())

    for i in range((key_index + 1) % n, key_index):
        temp = s[i] * G + c[i] * ring[i].pubkey.point
        c[(i + 1) % n] = hash_to_int(h + tag + temp.to_bytes())

    s[key_index] = (u - c[key_index] * private_key.privkey.secret_multiplier) % order

    return {
        'c0': c[0],
        's': s,
        'tag': tag.hex(),
        'ring': [vk.to_string().hex() for vk in ring],
        'message': message
    }

def verify(signature: dict) -> bool:
    """验证Linkable Ring Signature签名是否有效"""
    try:
        c = [0] * len(signature['s'])
        s = signature['s']
        ring = [VerifyingKey.from_string(bytes.fromhex(p), curve=curve) for p in signature['ring']]
        tag = bytes.fromhex(signature['tag'])
        h = sha256(signature['message'].encode())

        c[0] = signature['c0']
        for i in range(len(s)):
            temp = s[i] * G + c[i] * ring[i].pubkey.point
            c[(i + 1) % len(s)] = hash_to_int(h + tag + temp.to_bytes())

        return c[0] == c[-1]
    except Exception as e:
        print("Verification failed:", e)
        return False

def get_linkability_tag(signature: dict) -> str:
    """提取linkability tag用于防止双重投票"""
    return signature['tag']
