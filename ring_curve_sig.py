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
        return hashlib.sha256(x).digest()

    
    #encodes any integer
    def encode_int(self, x):
        return x.to_bytes(32, byteorder='big') # to test

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
    
    def sign(self, msg, pi, sk):
        #assume msg is a byte string
        pk = self.L[pi] 
        L = self.L
        #tag generation
        pk_x, pk_y = self.get_cord(pk.pubkey.point)   
        I = sk.privkey.secret_multiplier* self.hash_point(self.encode_int(pk_x)+self.encode_int(pk_y))
        #pi values
        s_pi = randrange(1,self.order_q) * self.order_q
        #Rπ=ψ.Hq(Pπ)
        R_pi = s_pi*self.hash_point(self.encode_int(pk_x)+self.encode_int(pk_y))
        print("I")
        c_list = []
        L_list = []
        s_list = []
        for i in range(len(L)):
            c_list.append(None)
            L_list.append(None)
            s_list.append(None)

        #c(π+1)mod N=ℏ(pku,Lπ,Rπ)
        L_list[pi] = s_pi*self.g
        c_list[(pi+1)%len(L)] = self.hash(msg+ L_list[pi] + R_pi )
        s_list[pi] = s_pi
        # generating random values for hashing per pk in L
        for i in range(1,len(L)):
            i = pi+i % len(L)
            si = s_list[i]
            ci = c_list[i]
            Li = si*self.g + ci*L[i]
            #point
            x,y = self.get_cord(L[i].pubkey.point)
            Ri = si*self.hash_point(x,y)
            #L_list[i] = si*self.g + ci*L[i]
            cocat = msg + Li + Ri
            next = (i+1)%len(L)
            c_list[next] = self.hash(cocat)
            #s_list[next] = (self. )%self.order_q 

        return (I, c_list[0],s_list)
    
    def verify(self, sig):
        
        return
    
    def link(self, sig):
        return
    
r = Linkable_Ring()
sk,pk = r.keygen()
pi = r.add_public_k(pk)
r.sign("hello", pi, sk)
k = SigningKey.generate(curve=NIST256p)
print(k.verifying_key.pubkey.point.y())