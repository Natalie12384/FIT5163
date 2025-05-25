from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP 
from Crypto.Random import get_random_bytes 
import math
import json
import ast
from ecdsa import NIST256p, SigningKey, ellipticcurve, VerifyingKey
import base64

# from filename import function

### encryption of vote value using secret key
class RSA_Encryption:
    @classmethod
    def encrypt(cls, msg, key, sig, L):
        #signature: (I, c_list[0],s_list) = (obj, int, int)

        #initialise set up
        cipher_rsa = PKCS1_OAEP.new(key) # allow detection of unauthorised modifications
        session_key = get_random_bytes(16)
        enc_session_key = cipher_rsa.encrypt(session_key) # Encrypt the session key with the public RSA key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)

        #convert everything to string
        b_tag = sig[0].to_bytes()
        str_link_tag = base64.b64encode(b_tag).decode("utf-8")
        str_c0 = str(sig[1])
        str_slist = json.dumps((sig[2]))
        str_L =[]
        for i in L:
            pk = i.to_pem().decode("utf-8")
            str_L.append(pk)
        str_L = json.dumps(str_L)

        #json object contains: msg, signature, L ring
        payload = {
            "msg": msg,
            "tag": str_link_tag,
            "c0": str_c0,
            "s_list": str_slist,
            "L": str_L
        }
        # convert json to string to be encoded into bytes
        json_string = json.dumps(payload)
        ct,tag = cipher_aes.encrypt_and_digest(json_string.encode("utf-8"))
        return ct, cipher_aes.nonce, tag, enc_session_key
    
    @classmethod
    def decrypt(cls, ct, sk, tag, enc_session_key, nonce):
        cipher_rsa = PKCS1_OAEP.new(sk)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        b_data = cipher_aes.decrypt_and_verify(ct, tag)
        str_data = b_data.decode("utf-8")

        #reform everything back to initial types/objects
        json_obj = json.loads(str_data)
        msg = json_obj["msg"]
        b_tag = base64.b64decode(json_obj["tag"])
        link_tag = ellipticcurve.PointJacobi.from_bytes(NIST256p.curve,b_tag)
        c0 = int(json_obj["c0"])
        s_list = json.loads(json_obj["s_list"])
        L = json.loads(json_obj["L"])
        L_list = []
        for i in L:
            L_list.append(VerifyingKey.from_pem(i))
        #reform signature
        signature = (link_tag,c0,s_list)
        return msg, signature, L_list
    
    def get_pub_key(cls):
        return RSA.import_key(open("receiver.pem").read())
    
    def get_priv_key(cls):
        return RSA.import_key(open("private.pem").read())


"""
def encrypt(msg, e_key):
    cipher = AES.new(e_key, AES.MODE_EAX) #placeholder mode of ops
    nonce = cipher.nonce
    ct, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ct,tag

### decryption of vote value using secret key
def decrypt(nonce, ct, tag, e_key):
    cipher = AES.new(e_key, AES.MODE_EAX, nonce=nonce) #placeholder mode of ops
    pt = cipher.decrypt(ct)
    try:
        cipher.verify(tag)
        return pt.decode('ascii')
    except:
        return False
"""   
v_key= RSA.generate(2048)
key = v_key.publickey()
cipher_rsa = PKCS1_OAEP.new(key) # allow detection of unauthorised modifications
session_key = get_random_bytes(16)
enc_session_key = cipher_rsa.encrypt(session_key) # Encrypt the session key with the public RSA key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
j = {"o":b"hello".decode("utf-8")}
b = json.dumps(j)
ct,tag = cipher_aes.encrypt_and_digest(b.encode("utf-8"))
nonce = cipher_aes.nonce

cipher_rsad = PKCS1_OAEP.new(v_key)
session_key1 = cipher_rsad.decrypt(enc_session_key)
cipher_aesd = AES.new(session_key1, AES.MODE_EAX, nonce=nonce)
data = cipher_aesd.decrypt_and_verify(ct, tag)

v = json.loads(data.decode("utf-8"))
print(v["o"])

