from pycocks.cocks import CocksPKG, Cocks

# 服务端：初始化 PKG（生成 p, q, n）
pkg = CocksPKG()

# 为 alice@example.com 生成私钥
r, a = pkg.extract("alice@example.com")

# 客户端使用 n 和 a 加密消息
client = Cocks(pkg.n)
cipher = client.encrypt(b"secret", a)

# 解密时使用私钥 r 和公钥 a
plain = client.decrypt(cipher, r, a)
print(plain)  # => b"secret"