from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP 
from Crypto.Random import get_random_bytes 
import math
from ecdsa import NIST256p, SigningKey, ellipticcurve, VerifyingKey
from ring_curve_sig import Linkable_Ring
from encryption import Encryption
import json, base64, sqlite3, hashlib, time
from datetime import datetime


# assume election authority
class VerifierServer:
    def __init__(self):
        #placeholder, to be replacced by IBE########################
        v_key= RSA.generate(2048) 
        private_key = v_key
        public_key = v_key.publickey()
        # save keys, assume its securely saved in the files
        with open("private.pem", "wb") as f:
            f.write(private_key.export_key())
        with open("receiver.pem", "wb") as f:
            f.write(public_key.export_key())
        ########################################

    def share_pubkey(self):
        return RSA.import_key(open("receiver.pem").read())
    
    def get_privkey(self):
        return RSA.import_key(open("private.pem").read())
    
    #verifies and add vote, signature and etc to database
    def verify_signature(self,ct, r,nonce, tag, enc_session_key):
        sk = self.get_privkey()
        #decrypt encryption
        msg, signature, L = Encryption.decrypt(ct,sk, tag, enc_session_key, nonce)
        #original vote in byte form for verification
        b_msg = msg.encode("utf-8")

        if r.verify(signature, L, b_msg ): #and r.check_link(signature[0]):
            #string 
            tag = signature[0]
            x,y = tag.x(), tag.y()
            primary_key = f"{x},{y}" #check linkability

            str_c0 = str(signature[1])
            str_slist = json.dumps((signature[2]))
            str_L =[]
            for i in L:
                pk = i.to_pem().decode("utf-8")
                str_L.append(pk)
            str_L = json.dumps(str_L)

            timestamp = datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
            hash_vote = hashlib.sha256(b_msg).hexdigest()

            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            try:
                c.execute('''INSERT into signatures (
                    tag, 
                    vote_hash,
                    c0, 
                    s_list,
                    ring_members, 
                    timestamp 
                    
              ) VALUES (?,?,?,?,?,?)''' ,(primary_key,hash_vote, str_c0, str_slist, str_L, timestamp))
                conn.commit()
                conn.close()
                return True, ""
            except sqlite3.IntegrityError as e:
                conn.close()
                return False, "Link tag already in system. Double Voting is not allowed"
            except Exception as e:
                conn.close()
                return False, str(e)
        else:
            return False, "Invalid signature and message pair"
            
        
    
    