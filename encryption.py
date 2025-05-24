from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP 
from Crypto.Random import get_random_bytes 
from ecdsa import SigningKey, ellipticcurve, VerifyingKey
import math
import json

# from filename import function

### encryption of vote value using secret key
class RSA_Encryption:
    def encrypt(cls, msg, key, sig, L):
        #signature: (I, c_list[0],s_list) = (obj, int, int)

        #initialise set up
        cipher_rsa = PKCS1_OAEP.new(key) # allow detection of unauthorised modifications
        session_key = get_random_bytes(16)
        enc_session_key = cipher_rsa.encrypt(session_key) # Encrypt the session key with the public RSA key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)

        #convert everything to string
        str_tag = sig[0].to_pem(format = "pkcs8").decode("utf-8")
        str_c0 = str(sig[1])
        str_slist = format(sig[2])
        str_L =[]
        for i in L:
            pk = i.to_pem(format = "pkcs8").decode("utf-8")
            str_L.append(pk)
        str_L = format(str_L)

        #json object contains: msg, signature, L ring
        payload = {
            "msg": msg,
            "tag": str_tag,
            "c0": str_c0,
            "s_list": str_slist,
            "L": str_L
        }
        # convert json to string to be encoded into bytes
        json_string = json.dumps(payload)
        ct,tag = cipher_aes.encrypt_and_digest(json_string.encode("utf-8"))
        return ct, cipher_aes.nonce, tag, enc_session_key
    
    def decrypt(cls, ct, sk, tag, enc_session_key, nonce):
        cipher_rsa = PKCS1_OAEP.new(sk)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ct, tag)

        #reform everything back to initial types/objects

        return 
    
    def get_pub_key(cls):
        return RSA.import_key(open("receiver.pem").read())
    
    def get_priv_key(cls):
        return RSA.import_key(open("private.pem").read())


## 
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

a =[1,2,3,4]
print(type(format(a)))
