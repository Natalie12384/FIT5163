from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import hashlib
import os
import time
import random
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'secure-voting-secret-key'

BLOCKCHAIN_FILE = 'blockchain.json'

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

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()


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


    for candidate in ['Alice', 'Bob']:
        c.execute('INSERT OR IGNORE INTO votes (candidate, count) VALUES (?, ?)', (candidate, 0))


    admin_username = 'admin'
    admin_password = hashlib.sha256('adminpass'.encode()).hexdigest()
    c.execute('INSERT OR IGNORE INTO users (username, password, voted, voted_for) VALUES (?, ?, 0, NULL)',
              (admin_username, admin_password))

    conn.commit()
    conn.close()

def generate_receipt(username, candidate):
    nonce = str(time.time()) + str(random.randint(1000, 9999))
    receipt = hashlib.sha256(f"{username}-{candidate}-{nonce}".encode()).hexdigest()
    vote_hash = hashlib.sha256(f"{candidate}-{nonce}".encode()).hexdigest()
    return receipt, vote_hash, nonce

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
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT voted FROM users WHERE username=?', (username,))
    voted = c.fetchone()[0]

    if voted == 1:
        return redirect('/already_voted')

    if request.method == 'POST':
        choice = request.form['candidate']
        receipt, vote_hash, nonce = generate_receipt(username, choice)
        c.execute('UPDATE votes SET count = count + 1 WHERE candidate = ?', (choice,))
        c.execute('UPDATE users SET voted = 1, voted_for = ? WHERE username = ?', (choice, username))
        c.execute('INSERT INTO vote_ledger (receipt, vote_hash) VALUES (?, ?)', (receipt, vote_hash))
        blockchain.create_block(vote_hash)
        conn.commit()
        conn.close()
        timestamp = datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
        return render_template('receipt.html', receipt=receipt, nonce=nonce, timestamp=timestamp)

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


if __name__ == '__main__':
    init_db()
    app.run(debug=True)

