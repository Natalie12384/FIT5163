### testing blind signatures
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES 
#from Crypto.Hash import HMAC
from Crypto.Random import get_random_bytes 
from Crypto.Hash import HMAC
import  Crypto.Random
import math

### Blind signature
# add more randomness 
def prepare_message(msg_byte): 
    nonce = get_random_bytes(16) 
    message = nonce+msg_byte
    hashed = hashlib.sha256(message).digest()
    #hashed_int = int.from_bytes(hashed, byteorder='big') % n
    return hashed, nonce

def blind_message(msg):
        r = random.randint(2,n-1)
        while math.gcd(r,n) != 1:
            r = random.randint(2,n-1)
        r_e = pow(r,e,n)
        blinded = (msg*r_e) % n
        return blinded,r

def sign_blind(b_msg):
    # sig` = (m`)^d mod n
    return pow(b_msg,d, n)

def unblind(sig, r):
    # sig = sig`*r^(-1) mod n
    r_1 = pow(r,-1,n)
    unb_sig = sig * (r_1)%n
    return unb_sig

def verify_unblind(sig,msg, nonce): 
    # sig = m^d mod n
    digest = hashlib.sha256(nonce+msg).digest()
    sig_digest = sig**e%n 
    return sig_digest == digest

