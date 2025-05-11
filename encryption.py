from Crypto.PublicKey import RSA
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes 
import  Crypto.Random
import math

"""
#RSA for key encryption - verifier owned
private_e_key  = RSA.generate(2048) #(n,d)
public_e_key = private_e_key.publickey() #(n,e)
d = private_e_key.d
e = private_e_key.e
n = private_e_key.n

# AES key gen for vote encryption - voter owned
aes_key = get_random_bytes(16)
"""

### encryption of vote value using secret key
def encrypt(msg, e_key):
    cipher = AES.new(e_key, AES.MODE_EAX) #placeholder mode of ops
    nonce = cipher.nonce
    ct, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ct,tag

def decrypt(nonce, ct, tag, e_key):
    cipher = AES.new(e_key, AES.MODE_EAX, nonce=nonce) #placeholder mode of ops
    pt = cipher.decrypt(ct)
    try:
        cipher.verify(tag)
        return pt.decode('ascii')
    except:
        return False