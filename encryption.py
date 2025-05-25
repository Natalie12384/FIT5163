from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP 
from Crypto.Random import get_random_bytes 
import math
import json
import ast
from ecdsa import NIST256p, SigningKey, ellipticcurve, VerifyingKey
import base64


from ring_curve_sig import Linkable_Ring

# from filename import function

### encryption of vote value using secret key
class Encryption:
    @classmethod
    def encrypt(cls, msg, key, sig, L): #takes msg, pub key, signature, list L ring
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

###Testing

v_key= RSA.generate(2048)
key = v_key.publickey()


r = Linkable_Ring()
sk,pk = r.keygen()
sk1,pk1 = r.keygen()
sk2,pk2 = r.keygen()
r.add_public_k(pk2)
pi = r.add_public_k(pk)
r.add_public_k(pk1)
sig = r.sign(b"hello", pi, sk,r.L)
ct, nonce, tag, enc_session_key = Encryption.encrypt("hello",key, sig, r.L)

msg, sig, L = Encryption.decrypt(ct, v_key,tag,enc_session_key,nonce)

#######################
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

