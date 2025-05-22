from sympy import isprime
from Crypto.Random.random import randrange, randint, getrandbits
import sqlite3
import hashlib
from Crypto.PublicKey import ECC
from ecdsa import NIST256p, SigningKey, ellipticcurve, VerifyingKey

class Linkable_Ring:
    def __init__(self):
        self.L = []
        self.curve = NIST256p #obj
        self.order_q = self.curve.order #int
        self.g = self.curve.generator #obj
        

    #produces another ring
    def hash_point(self, x):
        new_x = int.from_bytes(hashlib.sha256(x).digest(), "big" )%self.order_q
        point = new_x*self.g
        return point
    
    def hash(self, x):
        return int.from_bytes(hashlib.sha256(x).digest(), "big") %self.order_q

    #encodes any integer
    def encode_int(self, x):
        return x.to_bytes(32, byteorder='big') # to test
    
    def encode_point(self,x,y):
        return x.to_bytes(32, byteorder='big') + y.to_bytes(32, byteorder='big') 

    def add_public_k(self, pk):
        self.L.append(pk)
        return len(self.L) -1
    
    #to store in key vault
    def keygen(self): 
        key = SigningKey.generate(curve=NIST256p)
        private_key = key
        public_key = key.verifying_key
        return private_key, public_key

    def get_cord(self, point):
        y = point.y()  
        x = point.x()  
        return (x,y)
    
    def sign(self, msg, pi, sk, L):
        #assume msg is a byte string
        pk = self.L[pi] 
        c_list = []
        L_list = []
        s_list = []
        for i in range(len(L)):
            c_list.append(None)
            L_list.append(None)
            s_list.append(None)
        #tag generation
        pk_x, pk_y = self.get_cord(pk.pubkey.point)   
        pk_byte = self.encode_int(pk_x)+self.encode_int(pk_y)
        I = sk.privkey.secret_multiplier* self.hash_point(pk_byte)

        #pi values###########
        s_pi = randrange(1,self.order_q) 
        R_pi = s_pi*self.hash_point(pk_byte)
        L_list[pi] = s_pi*self.g
        x,y = self.get_cord(L_list[pi])   
        Li_byte = self.encode_int(x)+self.encode_int(y)
        x,y = self.get_cord(R_pi) 

        #c(pi+1)mod N=h(pku,Li,Ri) 
        c_list[(pi+1)%len(L)] = self.hash(msg+ Li_byte + self.encode_point(x,y) )
        s_list[pi] = s_pi
        # generating random values for hashing per pk in L
        for i in range(1,len(L)):
            i = (pi+i) % len(L) 
            si =randrange(1, self.order_q)
            s_list[i] = si #rand int
            ci = c_list[i]

            #Li
            Li = si*self.g + ci*L[i].pubkey.point
            #random point
            x,y = self.get_cord(L[i].pubkey.point)
            Ri_byte = self.encode_int(x)+self.encode_int(y) 
            Ri = si*self.hash_point(Ri_byte) + ci*I#

            #next c and s point in list
            next = (i+1)%len(L)    
            cocat = msg + self.encode_point(Li.x(), Li.y()) + self.encode_point(Ri.x(), Ri.y())
            c_list[next] = self.hash(cocat)
        s_list[pi] = (s_pi - c_list[pi]*sk.privkey.secret_multiplier) %self.order_q
        return (I, c_list[0],s_list)
    
    def verify(self, sig, L, msg):
        I = sig[0]
        c0 = sig[1] #int
        s_list = sig[2] #int
        c_list = [c0]
        
        #final c0
        final = None

        for i in range(len(L)): #O(L)
            #find Li
            Li = s_list[i]*self.g + L[i].pubkey.point *c_list[i]
            #find Ri
            x,y = self.get_cord(L[i].pubkey.point)
            Ri_byte = self.encode_int(x)+self.encode_int(y) 
            Ri = s_list[i]*self.hash_point(Ri_byte) + c_list[i]*I

            #hash
            cocat = msg + self.encode_point(Li.x(), Li.y()) + self.encode_point(Ri.x(), Ri.y())
            next = (i+1)%len(L)
            if next != 0:
                c_list.append(self.hash(cocat))
            else:
                final = self.hash(cocat)
        return c0 == final
    
    def insert_sig(self, sig, ct):
        tag = sig[0]
        x,y = tag.x(), tag.y()
        primary_key = f"{x},{y}"

        c0 =sig[1]
        
        s_list = str(sig[2])

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO votes (tag) VALUES (?)', (primary_key,))
            conn.commit()
            conn.close()
            return True

        except sqlite3.IntegrityError:
            conn.commit()
            conn.close()
            return False
    
    def check_link(self, I):
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('SELECT * FROM votes WHERE tag=?', (I,))
            user = c.fetchone()
            if user is None:
                return False
            return True
        except:
            return False

    #not tested
    def create_ring(self, pk):
        ring_size = 5
        L = []
        p_x, p_y = self.get_cord(pk)
        
        # Random index to place the input pk
        pi = randrange(ring_size)
        a = randrange(len(self.L))
        i = 0
        while i < 5:
            if i == pi:
                L.append(pk)
                i+=1
            i = (a+i)%self.L
            x,y = self.get_cord(self.L[i])
            if x != p_x and y != p_y:
                L.append(self.L[i])
            i+=1

        return L, pi
    
    def decode_pk(self, pk):
        return VerifyingKey.from_pem(pk)
    
    def decode_sk(self, sk):
        return SigningKey.from_pem(sk)
    

  
r = Linkable_Ring()
sk,pk = r.keygen()
sk1,pk1 = r.keygen()
sk2,pk2 = r.keygen()
r.add_public_k(pk2)
pi = r.add_public_k(pk)
r.add_public_k(pk1)



sig = r.sign(b"hello", pi, sk,r.L)
print(r.verify(sig, r.L, b"hello"))
#a = json.loads(s)  to convert str to list
conn = sqlite3.connect('database.db')
c = conn.cursor()
# just in case
c.execute('''DROP TABLE IF EXISTS votes''')
c.execute('''CREATE TABLE IF NOT EXISTS votes (
            tag TEXT PRIMARY KEY,
            c0 INTEGER,
            s_list TEXT
          )''')
conn.commit()
conn.close()
print(r.insert_sig(sig, None))

