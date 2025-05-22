from flask import Flask, render_template, request, redirect, session, url_for 
""" Flask 应用核心类，用来创建 Web 服务
# render_template	渲染 HTML 模板文件
# request	获取请求中的数据
# redirect	页面跳转
# session	管理用户登录状态
# url_for	生成 URL"""
import sqlite3 #连接 SQLite 数据库，用于存储用户和投票记录
import hashlib #提供哈希函数（如 SHA256），用于密码/身份哈希
import os #生成随机数、文件路径、操作系统交互等
import time #获取当前时间戳，用于投票时间记录、nonce 生成
import random #	生成伪随机数（非加密级），用于票据 nonce 等
import json #处理 JSON 数据，用于保存区块链数据到文件中
from datetime import datetime #时间格式化显示（如投票时间）
from passlib.hash import bcrypt #passlib 是一个流行的密码哈希库；bcrypt 是加盐密码哈希算法，安全性非常高；用于安全地存储用户密码，并验证登录密码。

BLOCKCHAIN_FILE = 'blockchain.json' #区块链以 JSON 文件形式存储；每一笔投票都形成一个区块，文件用于防篡改验证。

import cryptography
from cryptography.fernet import Fernet #对称加密
from cryptography.hazmat.primitives.asymmetric import rsa, padding  #生成密钥对（公钥/私钥）  在使用非对称加密（如 RSA）时添加填充，防止攻击
from cryptography.hazmat.primitives.kdf.hkdf import HKDF #密钥派生函数，常用于 IBE 或密钥共享协议中
from cryptography.hazmat.primitives import hashes, serialization #提供哈希算法接口  密钥的保存与加载
from Crypto.PublicKey import RSA #生成 RSA 密钥对（用于盲签名机制） （来自 pycryptodome 库）与 cryptography 库相比，这个库允许你直接访问私钥的数学属性（如 d, e, n）
from Crypto.Random import get_random_bytes #生成加密级别的随机字节（安全 nonce、盲因子等）
import Crypto.Random#提供强随机数生成器
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse#把消息从字节串转换为大整数   把大整数转换回字节串   	求模逆元，用于“unblind”盲签名时 r 的逆
import math # 提供数学函数； 用于验证 RSA 中的 r 是否与 n 互素。
import re # 正则表达式模块；在注册阶段校验邮箱格式

app = Flask(__name__)  
"""Flask 是 Flask 框架中的核心类。

app 是你创建的 Flask 应用对象，它会负责整个网站的路由处理、模板渲染、请求响应等。

参数 __name__ 是一个 Python 内置变量，表示当前模块的名称。

Flask 需要知道应用的“根路径”。

传入 __name__ 后，Flask 会根据你的模块位置，找到模板文件夹 templates/ 和静态文件夹 static/ 的路径。"""
app.secret_key = 'secure-voting-secret-key'
"""作用：保护 Session 和 Cookie 不被篡改
Flask 会使用这个密钥来加密和签名用户的 session 数据（如登录信息）。

防止攻击者伪造或修改 session 内容。

Flask 默认使用 客户端 Session（保存在 Cookie 中），这使得签名尤其重要。"""

# --- Identity Hash Function ---
def identity_hash(email):# 将每个用户的 email（如 alice@example.com）通过 SHA256 转换为一个固定身份指纹。这个哈希值具有唯一性和不可逆性（无法从哈希值反推出原始 email）。
    return hashlib.sha256(email.encode()).hexdigest()
"""email.encode()	将字符串 email 转为字节串（SHA256 要求字节输入）
hashlib.sha256(...)	使用 SHA256 哈希算法对字节数据进行加密散列
.hexdigest()	返回一个 64 位长度的十六进制字符串"""

# --- IBE Identity Checker (Mock) ---
def check_ibe_identity(email):
    """参数 email 是传入的用户身份标识（通常是注册或登录的邮箱地址）；

这个函数的目标是判断该邮箱是否属于受信任的身份列表（白名单）；

用于控制哪些用户被允许进行后续操作（如投票）。"""
    identity = identity_hash(email)
    """调用前面定义的 identity_hash() 函数（通常是 SHA256(email)）；

将 email（如 "alice@example.com"）转化为不可逆的身份指纹；

哈希后的身份值用于后续安全比对，防止明文 email 被直接比对或篡改。"""
    trusted = [identity_hash("admin@example.com"), identity_hash("user1@example.com")]
    """trusted 是一个 Python 列表，存储了两个邮箱地址对应的身份哈希值；

表示这两个邮箱是系统信任的用户，可以执行某些特权操作（如投票或管理）；

比对时不使用明文 email，而是使用其 hash，提升安全性和隐私。"""
    return identity in trusted
"""判断当前用户的身份哈希 identity 是否存在于 trusted 列表中；

返回布尔值 True 或 False：

如果存在于白名单中：✅ 表示“该用户受信任”；

如果不在其中：⛔ 表示“该用户不可信”，应拒绝其操作。"""

#rsa based keys for group signature
group_master_key = private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
"""group_master_key		IBE 主密钥 / 组签名密钥（身份派发、主签名）
private_key		        普通签名操作、盲签名使用
group_public_key		用于加密或验证签名，公开提供"""
"""public_exponent=65537	通常默认值	指定公钥指数，65537 是一个常用安全质数，运算快、抗攻击
key_size=2048	推荐最小值	密钥长度"""
group_public_key = group_master_key.public_key()

#RSA for blind signatures - signer pair  生成一对 RSA 密钥（私钥和公钥），并提取出其中的数学参数 d, e, n，用于 自定义加解密 / 盲签名 / 签名验证。
"""核心数学公式：
模数：n = p × q （两个大质数相乘）

欧拉函数：   φ(n) = (p-1)(q-1)

公钥指数：   e （通常选 65537，易算、抗攻击）

私钥指数：   d = e⁻¹ mod φ(n) （d 是 e 的模逆元）

"""
private_key  = RSA.generate(2048)
"""生成一个 RSA 密钥对，长度为 2048 位

内部随机生成两个大质数 p 和 q

计算出 n = p × q

自动选择 e = 65537（除非你另指定）

自动计算 d = e⁻¹ mod φ(n)

返回一个对象 private_key，它包含这些参数"""
public_key = private_key.publickey()
"""从私钥中派生出对应的公钥对象，只保留 n 和 e

public_key 仅包含：

e（公钥指数）

n（模数）

 用于：

验证签名

加密（尽管你项目不使用加密）

"""
d = private_key.d #提取出 RSA 私钥指数 d
e = private_key.e #提取出 RSA 公钥指数 e，通常是 65537  你会用它来：加密或在盲签名中计算 r^e mod n（盲化因子）
n = private_key.n #提取出 RSA 模数 n

#securely recording vote hashes
class Blockchain: #定义一个叫做 Blockchain 的类，表示一个最简单的“区块链”。

    def __init__(self):#初始化属性；设置初始状态；准备好后续功能所需要的数据结构。
        self.chain = []
        """self.chain 是一个用于存储“区块”的列表；

每一个区块是一个字典（dict）对象，包含：

index：区块编号（从 1 开始）；

timestamp：时间戳；

vote_hash：你想记录的投票内容（经过哈希）；

previous_hash：前一个区块的哈希值；

hash：当前区块自身的哈希值。

📌 初始状态：
刚创建对象时，链是空的；

所以这里给它赋值为 []；

但很快它会被 load_chain() 覆盖。"""
        self.load_chain()
        """尝试从本地加载已有的区块链数据（一般保存在 blockchain.json 文件中）；

如果文件存在，它就会把里面的数据读出来，赋值给 self.chain；

如果文件不存在（第一次运行程序），它就保留空链。"""

    def create_block(self, vote_hash):
        """你定义了 Blockchain 类中的一个方法 create_block，用来创建一个新区块。

self：指向当前 Blockchain 对象

vote_hash：你传进来的投票数据的哈希（如选票、签名等）"""
        previous_hash = self.chain[-1]['hash'] if self.chain else '0'
        """self.chain 是区块链，存储所有历史区块。

self.chain[-1]：获取链上最后一个区块（即最新的一个）。

['hash']：提取该区块的哈希值。

📌 两种情况：
情况	结果
链中已有区块	取最新区块的 hash
链是空的（第一次）	使用 '0' 作为 previous_hash，代表“创世区块”"""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'vote_hash': vote_hash,
            'previous_hash': previous_hash
        }
        """你创建了一个字典（dictionary）来代表新的区块，包含以下内容：
'index'	当前区块的编号，从 1 开始（因为链是列表，len(self.chain) + 1）
'timestamp'	当前时间的秒数（浮点型，来自 time.time()）
'vote_hash'	接收自函数参数，记录该选票的哈希值（不是明文）
'previous_hash'	与前一个区块形成“链”的关键字段"""
        block['hash'] = self.hash_block(block) 
        """为当前构造好的区块生成一个唯一的、不可逆的哈希值，并将其存入该区块的 hash 字段。
        为什么要给每个区块生成哈希？
因为：
✅ 哈希就像是 “指纹” —— 它唯一标识一个区块；

✅ 哈希能检测 任何微小改动（哪怕只改一个字母）；

✅ 哈希值用于“链接”区块（通过 previous_hash）形成 防篡改链条。

📌 一旦你修改区块中的内容（如 vote_hash），这个区块的 hash 就会改变，下一块的 previous_hash 就对不上了，从而链被破坏 → 被视为无效。"""
        self.chain.append(block) #将刚刚构造好的 block 加入 self.chain 末尾；相当于区块链新增了一个节点。顺序是线性的，按添加时间构建起来。
        self.save_chain() #将整个区块链写入到 JSON 文件（通常是 blockchain.json）中；这样即使 Flask 服务重启、程序崩溃，你的记录也会保存下来；实现持久化数据存储。
        return block #将这个区块作为函数返回值；可以用于：显示给用户；调试输出；保存票据；打印收据。



    def hash_block(self, block): #给传入的 block 区块计算一个 唯一且不可逆的数字指纹（哈希值）。
        block_copy = block.copy()
        """✅ 作用：
创建原始 block 字典的副本；

避免直接修改原区块数据，保持原数据不变；

是良好编程习惯，防止“副作用”。

🧠 为什么要复制？
因为接下来我们要删除 'hash' 字段，但不能破坏原始区块结构。"""
        block_copy.pop('hash', None)
        """✅ 作用：
从副本中删除 'hash' 字段（如果有）；

如果 block_copy 中没有 'hash'，也不会出错（None 是默认返回值）。

📌 为什么要删除 'hash' 字段？
这是一个关键步骤，因为：

❗️你正在为这个区块 生成哈希，而哈希值本身不能参与它自己的计算。

否则就变成了“循环依赖”：
区块的 hash 是区块的内容决定的，但内容又包含 hash，会造成死循环或不稳定值。

"""
        block_string = json.dumps(block_copy, sort_keys=True).encode()
        """分解讲解：
json.dumps(...)：把字典 block_copy 转换成字符串；

sort_keys=True：对字典中的键进行排序（按字母顺序）；

.encode()：将字符串转成字节串（bytes），供哈希算法处理。

🧠 为什么要排序？
因为：

JSON 对象的键在不同语言/系统中，顺序可能不同 → 产生的哈希值也会不同 ❌。"""
        return hashlib.sha256(block_string).hexdigest()
    """作用：
使用 hashlib 的 SHA-256 函数对字节串计算哈希；

.hexdigest() 表示输出 64 个字符的十六进制字符串。"""

    def save_chain(self):
        with open(BLOCKCHAIN_FILE, 'w') as f:
            """解释：
open(...) 是 Python 的内置文件操作函数；

'w' 模式表示写入模式（会清空旧文件）；

BLOCKCHAIN_FILE 是一个字符串变量，例如 'blockchain.json'；

with 是上下文管理器语法，确保文件用完后自动关闭。

🧠 为什么用 with？
→ 安全且自动释放资源，避免文件忘关。

"""
            json.dump(self.chain, f, indent=2)
            """解释：
json.dump() 是标准库中的函数，用于将 Python 对象写入文件；

self.chain 是一个列表（List），每个元素是一个字典（区块）；

f 是前面打开的文件句柄；

indent=2 会让 JSON 内容缩进 2 个空格，增强可读性。

"""

    def load_chain(self):
        if os.path.exists(BLOCKCHAIN_FILE):
            """BLOCKCHAIN_FILE 是一个字符串变量，定义了文件名，比如 'blockchain.json'；

os.path.exists(...) 是标准库 os 提供的函数，用来检查这个文件是否存在在磁盘上。"""
            with open(BLOCKCHAIN_FILE, 'r') as f:
                self.chain = json.load(f)
                """解释：
打开文件 blockchain.json，'r' 表示只读模式；

json.load(f) 会把文件内容解析为 Python 对象（列表 + 字典结构）；

结果赋值给 self.chain，恢复出整个链。"""
        else:
            self.chain = []
            """解释：
如果之前从未投过票或文件被删了，链就是空的；

此时我们初始化 self.chain = []，准备好接受第一个区块（即创世区块）。"""

blockchain = Blockchain()

# initialise database for users and vote
def init_db(): # 这表示定义一个初始化数据库的函数，在程序第一次运行或你想重置数据库时调用。
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    """database.db：本地 SQLite 数据文件

conn 是数据库连接对象

c 是 SQL 执行通道（cursor），你要靠它执行所有 SQL 命令"""
    c.execute('''DROP TABLE IF EXISTS users''')
    c.execute('''DROP TABLE IF EXISTS votes''')
    c.execute('''DROP TABLE IF EXISTS vote_ledger''')
    """ 删除旧表      这些语句确保你不会因为旧表结构冲突而报错；IF EXISTS 是保险，防止第一次运行时报错。"""

    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, 
                    password TEXT, 
                    voted INTEGER,
                    voted_for TEXT,
                    identity_hash TEXT)''')
    """用户表
username	TEXT	邮箱或用户名，作为唯一标识（主键）
password	TEXT	哈希过的密码（使用 bcrypt）
voted	INTEGER	是否已经投过票（0 / 1）
voted_for	TEXT	投给了谁（Alice 或 Bob）
identity_hash	TEXT	SHA-256(email)，用于身份绑定"""

    c.execute('''CREATE TABLE IF NOT EXISTS votes (
                    candidate TEXT PRIMARY KEY, 
                    count INTEGER)''')
    """字段说明：

candidate：候选人名字（如 Alice）

count：当前得票数

这是你投票之后需要更新的统计表。"""

    c.execute('''CREATE TABLE IF NOT EXISTS vote_ledger (
                    receipt TEXT PRIMARY KEY,
                    vote_hash TEXT)''')
    """receipt 是投票人拿到的投票回执编号（唯一）

vote_hash 是 vote 的哈希（可用于区块链验证）

🧠 这个表可用于审计与防篡改，结合区块链的 vote_hash 一致性校验。"""

    for candidate in ['Alice', 'Bob']:
        c.execute('INSERT OR IGNORE INTO votes (candidate, count) VALUES (?, ?)', (candidate, 0))
        """插入候选人 Alice、Bob 到 votes 表中；

OR IGNORE 避免重复插入报错；

初始得票数是 0。"""

    admin_username = 'admin'
    admin_password = bcrypt.hash('adminpass')
    admin_hash = identity_hash(admin_username)
    c.execute('INSERT OR IGNORE INTO users (username, password, voted, voted_for, identity_hash) VALUES (?, ?, 0, NULL, ?)',
              (admin_username, admin_password, admin_hash))
    """ 添加管理员账户,然后插入到用户表中：    
    admin 默认未投票
可以用于查看结果页面（通常 /admin/results）
密码为 adminpass，但哈希后存储"""

    conn.commit()
    conn.close()
    """commit() 是必须的，否则刚刚执行的 INSERT, CREATE 等命令不生效；

close() 用于释放连接资源。"""

def generate_receipt(username, candidate):
    """定义一个函数，用于在用户成功投票后生成三个值：

返回值	用途
receipt	发给用户保存的投票回执
vote_hash	用于写入区块链，记录投票内容
nonce	保证每一次 vote 都唯一、防止重放攻击"""
    nonce = str(time.time()) + str(random.randint(1000, 9999))
    """解释：
time.time()：获取当前系统时间（以秒为单位，带小数点）；

random.randint(1000, 9999)：再加一个四位随机数；

将它们拼接成字符串 → 形成一个时间+随机数混合的 nonce

🧠 为什么需要 nonce？
作用	说明
✅ 防止重复	每次投票都生成不同的 vote_hash 和 receipt
✅ 抗重放攻击	就算用户信息一样，每一次 hash 都不同
✅ 提供可验证的随机性	vote_hash 基于 nonce，可上链验证"""
    receipt = hashlib.sha256(f"{username}-{candidate}-{nonce}".encode()).hexdigest()
    """解释：
把用户名、候选人和 nonce 拼在一起形成字符串：

perl
复制
编辑
"alice@example.com-Bob-1715869.123456789842"
再对它进行 SHA-256 哈希处理；

结果是一个唯一的、不可逆的 64 位十六进制字符串。

📩 用户作用：
这个 receipt 通常会显示在投票成功页面，用户可以截图保存；
将来如果用户质疑投票结果，可以用它来验证自己的投票记录是否在链中。"""
    vote_hash = hashlib.sha256(f"{candidate}-{nonce}".encode()).hexdigest()
    """解释：
只用 candidate 和 nonce 生成哈希；

这表示用户选择了谁 + 当前这一刻（nonce）；

这就是写入区块链的内容！

"""
    return receipt, vote_hash, nonce
"""这个函数返回三件事：

返回值	用于什么？
receipt	显示给用户（投票成功页面）
vote_hash	写入区块链并存入数据库
nonce	可选保存，用于以后验证"""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    """@app.route(...) 是 Flask 的路由装饰器，定义这个函数响应哪个 URL 路径；

methods=['POST'] 表明此接口只接受 POST 请求（即用户提交表单）；

用户访问注册页面并提交表单时，这个函数就会被调用。"""
    username = request.form['username']
    password_raw = request.form['password']
    """request.form[...] 是 Flask 获取前端表单中 <input name="..."> 的值；

username 其实就是 email（虽然叫 username，但你强制它是邮箱格式）；

password_raw 是用户输入的明文密码（⚠️ 必须加密处理后再存数据库）。"""
    EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(EMAIL_REGEX, username):
        return "❌ Invalid email format. Please use a valid email address.", 400
    """为什么验证邮箱格式？
为了防止用户随便乱填不合法的名字；

同时你设计系统要求 username 是 email → 方便作为 IBE 的 Identity；

不合法则返回错误，状态码 400（Bad Request）。

整体结构解释
正则片段	      说明
^	        匹配字符串开头
[\w\.-]+	匹配用户名部分（如 alice.smith-123）
@	        必须包含 @ 符号
[\w\.-]+	匹配域名主机部分（如 gmail）
\.	        字面上的点 .（必须是点号）
\w+	        顶级域名（如 com、net）
$	        匹配字符串结尾
"""

    password = bcrypt.hash(password_raw)
    """说明：
bcrypt.hash(...) 使用 bcrypt 加盐哈希（安全加密算法）；

自动生成随机盐 + 多轮计算，防止彩虹表攻击；

最终结果是一个 不可逆的密文"""
    id_hash = identity_hash(username)
    """说明：
identity_hash(...) 是你自己定义的函数，用 SHA256 处理用户名（email）；

返回一个固定长度的哈希值：

这个值可以在身份验证（如模拟 IBE）中使用。"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    """连接 SQLite 数据库文件；

创建一个 SQL 游标，用于执行插入语句。"""
    try:
        c.execute('INSERT INTO users (username, password, voted, voted_for, identity_hash) VALUES (?, ?, 0, NULL, ?)', 
                  (username, password, id_hash))
        conn.commit()
    except:
        pass
    """解释：
username：用户的 email；

password：加密后的密码（不是明文）；

voted：初始为 0，表示未投票；

voted_for：初始为 NULL；

identity_hash：用于身份验证的哈希绑定。

使用 try/except 是为了防止重复注册导致程序崩溃（如主键冲突）。"""
    conn.close() # 关闭数据库连接，释放资源。
    return redirect('/') # 注册完成后，跳转回首页；

@app.route('/login', methods=['GET', 'POST'])
def login():
    """/login 是登录页面的 URL；

支持 GET 请求：展示登录表单；

支持 POST 请求：用户提交用户名与密码后执行验证逻辑。"""
    if request.method == 'POST':
        username = request.form['username']
        input_password = request.form['password']
        """request.form[...] 从表单中获取输入数据；

username 是用户填写的邮箱；

input_password 是用户填写的密码（明文，不能直接保存或比较！）"""
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()
        """说明：
conn = sqlite3.connect(...)：连接数据库；

c.execute(...)：执行 SQL 查询；

SELECT * FROM users WHERE username=?：

查找 users 表中用户名等于输入值的用户；

? 是参数占位符，防止 SQL 注入；

user = c.fetchone()：

如果查到了用户，返回一个 tuple，如：

('alice@example.com', '$2b$12$...', 0, None, 'a0dfe8...')
如果没查到用户，user 是 None。

"""
        if user and bcrypt.verify(input_password, user[1]):
            """user：确保数据库中有该用户；

user[1]：是用户表中 password 字段（哈希值）；

bcrypt.verify(...)：用 bcrypt 验证密码是否匹配：

input_password 是用户输入的明文密码；

user[1] 是数据库中存储的哈希值；

内部自动对比加盐哈希，安全可靠 ✅。"""
            session['user'] = username
            """Flask 内置 session 类似于浏览器的登录状态；

设置完 session['user'] 之后，表示该用户“已登录”；

后续其他受保护路由（如 /vote）可以检查 session 是否存在。"""
            return redirect('/admin/results' if username == 'admin' else '/vote')
        """如果是管理员（admin 用户名），就跳转到 /admin/results（投票结果）；

否则跳转到 /vote 页面，让用户投票。"""
    return render_template('login.html')
"""如果是 GET 请求，就展示登录页面；

如果用户不存在或密码错误，也跳回登录页。"""

@app.route('/logout')
def logout():
    session.clear()  
    return redirect('/')# 清除 session，强制用户重新登录。session.clear() 会把用户 session 里的所有信息都清除掉；也就是说，用户“退出登录”了；下一次再访问受保护页面（如 /vote），必须重新登录。
#session 就是用来记录“用户当前登录状态”的字典。它是服务器在用户登录后创建的一段会话数据，用来记住这个用户是谁、是否已经登录、以及登录时的相关信息。


def sign_blind(blinded_msg):
    d = private_key.d
    n = private_key.n
    signed = pow(blinded_msg, d, n)  
    return signed
"""作用：
使用 RSA 私钥 d 对盲化后的消息进行签名；

签名服务器 并不知道实际内容，保护隐私。

🧠 解释：
行	内容	说明
pow(blinded_msg, d, n)	RSA 签名公式：s = m^d mod n	只不过这里是盲化消息 m_b
return signed	签名结果是整数 s	还需解盲才能用于验证"""

def prepare_message(param): # param 是一个参数变量名，通常表示你传进来的数据。在你的投票系统里，param 通常是：💡 你投票选择的候选人名字（如 "Alice" 或 "Bob"）的字节表示。
    nonce = os.urandom(16)
    msg = hashlib.sha256(param + nonce).digest()
    return msg, nonce
"""作用：
准备要签名的消息（即投票内容），加上 随机数 nonce，防止重放攻击；

将票据哈希成定长值，避免明文投票暴露。

🧠 解释：
行	内容	说明
os.urandom(16)	随机生成 16 字节 nonce	用于防止投票重复、可追溯性
param + nonce	拼接候选人名和随机数	投票人对 “Alice+随机” 投票
hashlib.sha256(...).digest()	生成固定长度的哈希值	准备加密和盲化的消息

"""

def blind_message(msg_bytes):
    e = public_key.e
    n = public_key.n
    m = bytes_to_long(msg_bytes)
    while True:
        r = random.randrange(2, n)
        if math.gcd(r, n) == 1:
            break
    blinded = (m * pow(r, e, n)) % n
    return blinded, r
"""作用：
将投票消息“盲化”，使签名服务器无法知道真实内容；

实现隐私保护，避免追踪投票内容。

🧠 解释：
行	内容	说明
e, n	RSA 公钥	签名验证用的是公钥 (e, n)
bytes_to_long(msg_bytes)	把哈希消息转为整数	为了参与模幂运算
r = ...	随机生成盲因子 r（与 n 互质）	防止泄露真实消息
blinded = (m * r^e) % n	盲化公式：RSA blind	让 signer 签署的是“遮住”的消息
return blinded, r	返回盲化消息 + r	r 用于后续解盲"""

def unblind(signed_blinded, r):
    n = public_key.n
    r_inv = pow(r, -1, n)
    unblinded = (signed_blinded * r_inv) % n
    return unblinded
"""作用：
取消盲因子 r 的影响，恢复真实签名；

得到最终对消息 m 的签名：sig = m^d mod n

🧠 解释：
        行	                         内容	                              说明
r_inv = pow(r, -1, n)	        计算 r 的模逆	                       满足 r * r_inv ≡ 1 mod n
signed_blinded * r_inv % n	    解盲公式：(m_b^d) * r^-1 ≡ m^d	       得到最终签名
return unblinded	            这是 vote 的真实签名	                可公开验证，无需暴露原始消息
"""

def verify_vote(signature, msg_bytes):
    e = public_key.e
    n = public_key.n
    m = bytes_to_long(msg_bytes)
    check = pow(signature, e, n)
    return check == m
"""作用：
用公钥 (e, n) 验证签名的合法性；

核对 sig^e ≟ msg，确保签名真实有效；

检查是否被篡改、伪造。

🧠 解释：
        行	                            内容	                     说明
pow(signature, e, n)	       公钥验证公式：sig^e ≡ msg	     RSA 签名验证逻辑
check == m	                   判断签名是否匹配消息	              若不等则说明签名无效或篡改
"""