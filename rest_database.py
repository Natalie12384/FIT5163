import sqlite3
from blockchain import Blockchain

blockchain = Blockchain()
conn = sqlite3.connect('database.db')
c = conn.cursor()
# reset database
c.execute('''DROP TABLE IF EXISTS users''')
c.execute('''DROP TABLE IF EXISTS votes''')
c.execute('''DROP TABLE IF EXISTS vote_ledger''')
c.execute('''DROP TABLE IF EXISTS votes''')
c.execute('''DROP TABLE IF EXISTS signatures''')
c.execute('''DROP TABLE IF EXISTS user_key_vault''')
blockchain.clear_chain()
conn.close()