from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import hashlib
import os
import time
import random
import json
from datetime import datetime
BLOCKCHAIN_FILE = 'blockchain.json'

import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
### testing blind signatures
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes 
import Crypto.Random 
import math

app = Flask(__name__)

app.secret_key = 'secure-voting-secret-key' # this is only session security, not group signature

#rsa based keys for group signature
group_master_key = private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
group_public_key = group_master_key.public_key

#RSA for blind signatures - signer pair
private_key  = RSA.generate(2048)
public_key = private_key.publickey()
d = private_key.d
e = private_key.e
n = private_key.n

## Key related functions for group signature - bad
"""
def generate_user_key(username): # generates new key for given user
    info = username.encode() #encode username to bytes
    salt = os.urandom(16)
    #initialise key derivation object
    hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=info,
    )  
    #create new key from master key
    #convert master key into bytes
    private_bytes = group_master_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
    )
    #derive key
    user_key = hkdf.derive(private_bytes)
    return user_key, salt, info

def sign_vote(message_hash, key):
    signature = key.sign(
        message_hash, 
        padding,padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        )
    return signature
 
def verify_signature(signature, message):
    return group_public_key.verify(
    signature,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

key = generate_user_key("test")
#signature = sign_vote("test1", key)
print(key[0])
#print(verify_signature(signature,"test1" ))    
"""
### Blind signature
def prepare_message(msg_byte): # add more randomness into, since voting is 2 options
    nonce = get_random_bytes(16) 
    message = nonce+msg_byte
    hashed = hashlib.sha256(message).digest()
    hashed_int = int.from_bytes(hashed, byteorder='big') % n
    return hashed_int, nonce

def blind_message(msg):
        r = random.randint(2,n-1)
        while math.gcd(r,n) != 1:
            r = random.randint(2,n-1)
        r_e = pow(r,e,n)
        blinded = (msg*r_e) % n
        return blinded,r

def sign_blind(msg):
    return pow(msg,d, n)

def verify_unblind(sig,vote, nonce): #need work,think its wrong
    digest = hashlib.sha256(nonce+vote).digest()
    sig_digest = sig**e%n 
    return sig_digest == digest

def unblind(sig, r):
    r_1 = pow(r,-1,n)
    unb_sig = sig * (r_1)%n
    return unb_sig

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
    #c.execute('''DROP TABLE IF EXISTS user_key_vault''')

    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY, 
                    password TEXT, 
                    voted INTEGER,
                    voted_for TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS votes (
                    candidate TEXT PRIMARY KEY, 
                    count INTEGER)''')

    c.execute('''CREATE TABLE IF NOT EXISTS vote_ledger (
                    receipt TEXT PRIMARY KEY,
                    vote_hash TEXT)''')
    
    #this is a table that stores current group keys
    """c.execute('''Create table if not exists user_key_vault(
                username Text primary key,
                salt blob,
                info Blob,
                encrypted_key Text
              )''')"""

    for candidate in ['Alice', 'Bob']:
        c.execute('INSERT OR IGNORE INTO votes (candidate, count) VALUES (?, ?)', (candidate, 0))

    #hardcode voting authority user to view votes
    admin_username = 'admin'
    admin_password = hashlib.sha256('adminpass'.encode()).hexdigest()
    c.execute('INSERT OR IGNORE INTO users (username, password, voted, voted_for) VALUES (?, ?, 0, NULL)',
              (admin_username, admin_password))

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
    password = hashlib.sha256(request.form['password'].encode()).hexdigest()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password, voted, voted_for) VALUES (?, ?, 0, NULL)', (username, password))
        conn.commit()
    except:
        pass
    conn.close()
    return redirect('/')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        user = c.fetchone()
        conn.close()
        if user:
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
        msg, nonce = prepare_message(choice.encode())
        blinded_msg,r = blind_message(msg)
        #check for user
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT voted FROM users WHERE username=?', (username,))
        voted = c.fetchone()[0]
        if voted == 1:
            return redirect('/already_voted')
        else:
            #sign vote
            signature = sign_blind(blinded_msg)
            timestamp = datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
            return render_template('receipt.html', receipt=signature, nonce=nonce, timestamp=timestamp, r = r)
        

        """ previous code has no security
        receipt, vote_hash, nonce = generate_receipt(username, choice)
        c.execute('UPDATE votes SET count = count + 1 WHERE candidate = ?', (choice,))
        c.execute('UPDATE users SET voted = 1, voted_for = ? WHERE username = ?', (choice, username))
        c.execute('INSERT INTO vote_ledger (receipt, vote_hash) VALUES (?, ?)', (receipt, vote_hash))
        blockchain.create_block(vote_hash)
        conn.commit()
        conn.close()
        timestamp = datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
        return render_template('receipt.html', receipt=receipt, nonce=nonce, timestamp=timestamp)
        """

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


@app.route('/verify_vote')
def verify_vote():
    signature, nonce,r = request.form['receipt','nonce', 'r']
    unb_sig = unblind(signature, r)
    if verify_unblind(unb_sig, nonce):

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        #c.execute('UPDATE votes SET count = count + 1 WHERE candidate = ?', (choice,))
        #c.execute('UPDATE users SET voted = 1, voted_for = ? WHERE username = ?', (choice, username))
        #c.execute('INSERT INTO vote_ledger (receipt, vote_hash) VALUES (?, ?)', (receipt, vote_hash))
    return

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

