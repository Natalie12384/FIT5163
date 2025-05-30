from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes 
from encryption import Encryption
import json, sqlite3, hashlib, time
from datetime import datetime
from blockchain import Blockchain

from ring_curve_sig import Linkable_Ring
from blockchain import Blockchain

# assume election authority
class VerifierServer:
    def __init__(self, blockchain, ring, sk, pk, ibe):
        self.sk = sk
        self.pk = pk
        self.ibe = ibe
        # save keys, assume its securely saved in the files
        """
        with open("private.pem", "wb") as f:
            f.write(private_key.export_key())
        with open("receiver.pem", "wb") as f:
            f.write(public_key.export_key())
        ########################################
        """
        self.blockchain = blockchain
        self.ring = ring

    def share_pubkey(self):
        return self.pk
    
    def get_privkey(self):
        return self.sk
    
    #verifies and add vote, signature and etc to database
    def verify_signature(self,ct, r,nonce, tag, enc_session_key):
        sk = self.sk
        pk = self.pk
        ring = self.ring
        #decrypt encryption
        msg, signature, L = Encryption.decrypt(ct, tag, enc_session_key, nonce, self.ibe, pk,sk,)
        #original vote in byte form for verification
        b_msg = msg.encode("utf-8")

        if not self.check_ring(L):
            return False, "Signature construction is not valid"

        if ring.verify(signature, L, b_msg ): 
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
            hash_vote = hashlib.sha256(b_msg+timestamp.encode("utf-8")).hexdigest() #hashed with time

            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            try:
                #save signature
                c.execute('''INSERT into signatures (
                    tag, 
                    vote_hash,
                    c0, 
                    s_list,
                    ring_members, 
                    timestamp 
                    
              ) VALUES (?,?,?,?,?,?)''' ,(primary_key,hash_vote, str_c0, str_slist, str_L, timestamp))
                
                #generate receipt
                receipt = self.generate_receipt(primary_key,hash_vote)
                #add to vote ledger
                c.execute('''INSERT into vote_ledger (
                    receipt,
                    vote_hash      
                    
              ) VALUES (?,?)''' ,
              (receipt,hash_vote)
              )
                
                #add to tally
                c.execute('''UPDATE votes SET count = count + 1 
                          WHERE candidate = (?)''',(msg,) )

                conn.commit()
                conn.close()

                #add to block chain
                block = self.blockchain.create_block(hash_vote, receipt)

                return True, receipt
            except sqlite3.IntegrityError as e:
                conn.close()
                return False, "It seems you have already voted! Reminder that you can only vote once."
            except Exception as e:
                conn.close()
                return False, str(e)
        else:
            return False, "Invalid signature and message pair"

    #generate receipt after successfult vote verification    
    def generate_receipt(self, tag_primarykey, vote ):
        nonce = get_random_bytes(16)
        string = nonce+tag_primarykey.encode("utf-8")+vote.encode("utf-8") 
        receipt = hashlib.sha256(string).hexdigest()
        return  receipt 

    
    #check if ring list is part of ring (valid registered voters)
    def check_ring(self,L):
        ring = self.ring
        L_set = self.ring.get_L_set()
        for i in L:
            ringx, ringy = ring.get_cord(i.pubkey.point)
            if (ringx,ringy) not in L_set:
                return False
        return True 
