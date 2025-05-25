from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import hashlib
import os
import time
import random
import json
from datetime import datetime
BLOCKCHAIN_FILE = 'blockchain.json'

# importing functions from files
from encryption import Encryption
from ring_curve_sig import Linkable_Ring
from verifier_server import VerifierServer

#password system
from passlib.hash import bcrypt 
import re 


### testing blind signatures
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes 
import  Crypto.Random
import math

########will delete
def prepare_message(msg_byte): 
    nonce = get_random_bytes(16) 
    message = nonce+msg_byte
    hashed = hashlib.sha256(message).digest()
    #hashed_int = int.from_bytes(hashed, byteorder='big') % n
    return hashed, nonce

#generate key pair for verifierd
verifier = VerifierServer()
public_key = verifier.share_pubkey()

app = Flask(__name__)

app.secret_key = 'secure-voting-secret-key' # this is only session security, not group signature

#initialise ring
ring = Linkable_Ring()

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

#securely recording vote hashes
class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

    def create_block(self, vote_hash):
        previous_hash = self.chain[-1]['hash'] if self.chain else '0'
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'vote_hash': vote_hash,
            'previous_hash': previous_hash
        }
        block['hash'] = self.hash_block(block)
        self.chain.append(block)
        self.save_chain()
        return block

    def hash_block(self, block):
        block_copy = block.copy()
        block_copy.pop('hash', None)
        block_string = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def save_chain(self):
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump(self.chain, f, indent=2)

    def load_chain(self):
        if os.path.exists(BLOCKCHAIN_FILE):
            with open(BLOCKCHAIN_FILE, 'r') as f:
                self.chain = json.load(f)
        else:
            self.chain = []

blockchain = Blockchain()

# initialise database for users and vote
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # just in case
    c.execute('''DROP TABLE IF EXISTS users''')
    c.execute('''DROP TABLE IF EXISTS votes''')
    c.execute('''DROP TABLE IF EXISTS vote_ledger''')
    c.execute('''DROP TABLE IF EXISTS votes''')

    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, 
                    password TEXT, 
                    voted INTEGER,
                    voted_for TEXT,
                    identity_hash TEXT,
                    encrypted_sk Text
              )''')

    c.execute('''CREATE TABLE IF NOT EXISTS votes (
                    candidate TEXT PRIMARY KEY, 
                    count INTEGER)''')

    c.execute('''CREATE TABLE IF NOT EXISTS vote_ledger (
                    receipt TEXT PRIMARY KEY,
                    vote_hash TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS signatures (
                    tag TEXT Primary key,
                    vote_hash TEXT NOT_NULL,
                    c0 TEXT NOT_NULL,
                    s_list TEXT NOT_NULL,
                    ring_members TEXT NOT_NULL,
                    timestamp TEXT
                    
              )''')
   

    for candidate in ['Alice', 'Bob']:
        c.execute('INSERT OR IGNORE INTO votes (candidate, count) VALUES (?, ?)', (candidate, 0))

    #hardcode voting authority user to view votes
    admin_username = 'admin'
    admin_password = bcrypt.hash('adminpass')
    admin_hash = identity_hash(admin_username)
    c.execute('INSERT OR IGNORE INTO users (username, password, voted, voted_for, identity_hash, encrypted_sk) VALUES (?, ?, 0, NULL, ?, NULL)',
              (admin_username, admin_password, admin_hash))
    conn.commit()
    conn.close()

#generate receipt for successful voting submissions
def generate_receipt(username, candidate):
    nonce = str(time.time()) + str(random.randint(1000, 9999))
    receipt = hashlib.sha256(f"{username}-{candidate}-{nonce}".encode()).hexdigest()
    vote_hash = hashlib.sha256(f"{candidate}-{nonce}".encode()).hexdigest()
    return receipt, vote_hash, nonce

#initial page- get 
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password_raw = request.form['password']
    EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(EMAIL_REGEX, username):
        return "❌ Invalid email format. Please use a valid email address.", 400
    password = bcrypt.hash(password_raw)
    id_hash = identity_hash(username)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        #generate keypair
        sk, pk = ring.keygen()
        ring.add_public_k(pk)
        #convert to string
        sk = sk.to_pem().decode("utf-8")
        #encrypt sk
        #####################################
        c.execute('INSERT INTO users (username, password, voted, voted_for,identity_hash, encrypted_sk) VALUES (?, ?, 0, NULL, ?,?)', (username, password, id_hash, sk))
        conn.commit()
    except Exception as e:
        print(e)
        return redirect('/')
    conn.close()
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        input_password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and bcrypt.verify(input_password, user[1]):
            session['user'] = username
            return redirect('/admin/results' if username == 'admin' else '/vote')
    return render_template('login.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'user' not in session:
        return render_template('error.html', message="You must be logged in to access this page.")
    username = session['user']

    if request.method == 'POST':
        choice = request.form['candidate']
        msg, nonce = prepare_message(choice.encode("utf-8")) #placeholder
        msg = choice.encode("utf-8")
        #check for user
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT voted FROM users WHERE username=?', (username,))
        voted = c.fetchone()[0]
        if voted == 1:
            return redirect('/already_voted')
        else:
            c.execute('SELECT encrypted_sk FROM users WHERE username=?', (username,))
            enc_sk = c.fetchone()[0]
            conn.close()
            #decrypt the sk
            ###################################
            dec_sk = enc_sk
            ###################################
            # Get parameters
            sk = ring.decode_sk(dec_sk)
            pk = sk.verifying_key
            L, pi = ring.create_ring(pk)
            #sign
            signature = ring.sign(msg, pi, sk, L )
            ct, nonce, tag, enc_session_key = Encryption.encrypt(choice, public_key, signature,L)
            #talk to verifier
            success, result = verifier.verify_signature(ct,ring,nonce, tag, enc_session_key)
            if success:
                timestamp = datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
                return render_template('receipt.html', receipt=result, timestamp=timestamp)
            else:
                return render_template ('error.html', message = result)

    return render_template('vote.html', voted=False)

@app.route('/already_voted')
def already_voted():
    return render_template('already_voted.html')

@app.route('/myvote')
def myvote():
    if 'user' not in session:
        return redirect('/login')

    username = session['user']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT voted, voted_for FROM users WHERE username=?', (username,))
    result = c.fetchone()
    conn.close()

    return render_template('myvote.html', voted=(result[0] == 1), voted_for=result[1] if result[0] == 1 else None)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    vote_hash = None
    found = False
    if request.method == 'POST':
        candidate = request.form['candidate']
        nonce = request.form['nonce']
        vote_hash = hashlib.sha256(f"{candidate}-{nonce}".encode()).hexdigest()
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT 1 FROM vote_ledger WHERE vote_hash=?', (vote_hash,))
        found = c.fetchone() is not None
        conn.close()
    return render_template('verify.html', found=found, vote_hash=vote_hash)

@app.route('/blockchain')
def view_blockchain():
    with open(BLOCKCHAIN_FILE, 'r') as f:
        chain = json.load(f)
        for block in chain:
            block['readable_time'] = datetime.fromtimestamp(block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
    return render_template('blockchain.html', chain=chain)

@app.route('/blockchain/search', methods=['GET', 'POST'])
def search_blockchain():
    found_block = None
    search_hash = None
    if request.method == 'POST':
        search_hash = request.form['vote_hash']
        with open(BLOCKCHAIN_FILE, 'r') as f:
            chain = json.load(f)
            for block in chain:
                if block['vote_hash'] == search_hash:
                    block['readable_time'] = datetime.fromtimestamp(block['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
                    found_block = block
                    break
    return render_template('blockchain_search.html', found=found_block, vote_hash=search_hash)

@app.route('/result')
def result():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT candidate, count FROM votes')
    results = c.fetchall()
    conn.close()
    return render_template('result.html', results=results)

@app.route('/admin/results', methods=['GET', 'POST'])
def admin_results():
    if 'user' not in session or session['user'] != 'admin':
        return "<h3>Access Denied. Admins only.</h3><a href='/'>Home</a>"

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')
        if action == 'delete':
            c.execute('SELECT voted_for FROM users WHERE username=?', (username,))
            voted_for = c.fetchone()
            if voted_for and voted_for[0]:
                c.execute('UPDATE votes SET count = count - 1 WHERE candidate = ?', (voted_for[0],))
            c.execute('DELETE FROM users WHERE username=? AND username != "admin"', (username,))
        elif action == 'reset':
            c.execute('SELECT voted_for FROM users WHERE username=?', (username,))
            voted_for = c.fetchone()
            if voted_for and voted_for[0]:
                c.execute('UPDATE votes SET count = count - 1 WHERE candidate = ?', (voted_for[0],))
            c.execute('UPDATE users SET voted = 0, voted_for = NULL WHERE username=? AND username != "admin"', (username,))
        conn.commit()

    c.execute('SELECT candidate, count FROM votes')
    results = c.fetchall()

    c.execute('SELECT username, voted_for FROM users')
    records = c.fetchall()
    conn.close()

    return render_template('admin_results.html', records=records, results=results)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/result/chart')
def result_chart():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT candidate, count FROM votes')
    results = c.fetchall()
    conn.close()
    return render_template('result_chart.html', results=results)

@app.route('/result/chart')
def result_chart():

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

