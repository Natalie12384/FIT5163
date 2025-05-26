from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import hashlib
import os
import time
import random
import json
from ecdsa import SigningKey, VerifyingKey
from datetime import datetime


# importing functions from files
from encryption import Encryption
from ring_curve_sig import Linkable_Ring
from IBE_server import IBEServer
from verifier_server import VerifierServer
from blockchain import Blockchain

#password system
from passlib.hash import bcrypt 
import re 

#initialise blockchain
BLOCKCHAIN_FILE = 'blockchain.json'
blockchain = Blockchain()

#initialise ring
ring = Linkable_Ring()

#Initiaise Election Authority - verifier
verifier = VerifierServer(blockchain, ring)
public_key = verifier.share_pubkey()

#session Authentication
app = Flask(__name__)
app.secret_key = 'secure-voting-secret-key' # this is only session security

# initialise IBE server
# modified the source code of pycocks the PKG is fixed now
ibe_server = IBEServer()

# --- Identity Hash Function ---
def identity_hash(email): 
    return hashlib.sha256(email.encode()).hexdigest()

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
                    identity_hash TEXT
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
    c.execute('INSERT OR IGNORE INTO users (username, password, voted, voted_for, identity_hash) VALUES (?, ?, 0, NULL, ?)',
              (admin_username, admin_password, admin_hash))
    conn.commit()
    conn.close()

def generate_key_pair(username):
    sk_ibe, pk_ibe = ibe_server.client_key_pair_gen(username)
    hashed_pk = identity_hash(str(pk_ibe)) # hash the pk
    sk_curve, pk_curve = ring.int_to_keys(hashed_pk) # (SigningKey, VerifyingKey)
    sk_pem = sk_curve.to_pem().decode("utf-8")
    pk_pem = pk_curve.to_pem().decode("utf-8")
    return  sk_curve, pk_curve, sk_pem, pk_pem

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
        # #generate keypair
        # sk, pk = ring.keygen()
        # ring.add_public_k(pk)
        # #convert to string
        # sk = sk.to_pem(format = "pkcs8").decode("utf-8")
        # --- IBE Method ---
        #generate keypair from IBE server
        sk_ibe, pk_ibe = ibe_server.client_key_pair_gen(username)
        hashed_pk = identity_hash(str(pk_ibe)) # hash the pk
        sk_curve, pk_curve, sk_pem, pk_pem = generate_key_pair(username)
        ring.add_public_k(pk_curve)
        #encrypt sk
        #####################################
        c.execute('INSERT INTO users (username, password, voted, voted_for,identity_hash) VALUES (?, ?, 0, NULL, ?)', (username, password, id_hash))
        conn.commit()
    except Exception as e:
        print(e)
        return render_template('index.html', message="❌ Registration failed. Already in system.")
    conn.close()
    return render_template('index.html', message="✅ Student has registered successfully!")

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
            return redirect('/admin/results' if username == 'admin' else '/home')
        
        return render_template('index.html', login_message="❌ Incorrect Password or Username")
    return render_template('login.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'user' not in session:
        return render_template('error.html', message="You must be logged in to access this page.")
    username = session['user']

    if request.method == 'POST':
        choice = request.form['candidate']
        msg = choice.encode("utf-8")
        #check for user
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT voted FROM users WHERE username=?', (username,))
        voted = c.fetchone()[0]
        if voted == 1:
            return redirect('/already_voted')
        else:
            #decrypt the sk
            ###################################
            sk_curve, pk_curve, sk_pem, pk_pem = generate_key_pair(username)
            dec_sk = sk_pem
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

@app.route('/home')
def home():
    if 'user' in session:
        username = session['user']
        return render_template('home.html', username=username)
    else:
        return redirect('/')

@app.route('/verify_myvote', methods=['GET', 'POST'])
def verify_myvote():
    if 'user' not in session:
        return redirect('/')
    found = False
    if request.method == 'POST':
        receipt = request.form['receipt']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT 1 FROM vote_ledger WHERE receipt=?', (receipt,))
        found = c.fetchone() is not None
        conn.close()
        return render_template('test_verify_myvote.html', found=found, receipt=receipt)
    return render_template('test_verify_myvote.html')
    

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

"""
#generate receipt for successful voting submissions
def generate_receipt(username, candidate):
    nonce = str(time.time()) + str(random.randint(1000, 9999))
    receipt = hashlib.sha256(f"{username}-{candidate}-{nonce}".encode()).hexdigest()
    vote_hash = hashlib.sha256(f"{candidate}-{nonce}".encode()).hexdigest()
    return receipt, vote_hash, nonce
"""