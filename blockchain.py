from flask import Flask, render_template, request, redirect, session, url_for
import hashlib
import os
import time
import json

BLOCKCHAIN_FILE = 'blockchain.json'

#securely recording vote hashes
class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

    def create_block(self, vote_hash, receipt):
        previous_hash = self.chain[-1]['hash'] if self.chain else '0'
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'vote_hash': vote_hash,
            'previous_hash': previous_hash,
            'receipt': receipt
            
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

    def chain_valid(self):

        return
b = Blockchain()
print(b.chain)