from sympy import isprime
from Crypto.Random.random import randrange, randint, getrandbits
import sqlite3
import hashlib
from Crypto.PublicKey import ECC
from ecdsa import NIST256p, SigningKey, ellipticcurve, VerifyingKey

class Linkable_Ring:
    """
    Initialises linkable ring signature using elliptic curves
    Attributes:
        curve: Curve model object
        order_q: integer
        g: generator object
    """
    def __init__(self):
        self.L = []
        self.curve = NIST256p #obj
        self.order_q = int(self.curve.order) #int
        self.g = self.curve.generator #obj
        self.L_points = set()

    def get_L_set(self):
        return self.L_points

    #produces another ring element
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
        self.L_points.add(self.get_cord(pk.pubkey.point))
        return len(self.L) -1
    
    #to store in key vault
    def keygen(self): 
        key = SigningKey.generate(curve=NIST256p, entropy=None, hashfunc=hashlib.sha256) 
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
        I = sk.privkey.secret_multiplier* self.hash_point(pk_byte) #JacobiPoint object

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
        I = sig[0] #JacobiPoint object
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

    def create_ring(self, pk):
        ring_size = 5
        L = []
        p_x, p_y = self.get_cord(pk.pubkey.point)
        
        # Random index to place the input pk
        pi = randrange(0,ring_size)
        a = 0
        if len(self.L) <5 and len(self.L)>0:
            for i in range(len(self.L)):
                x,y = self.get_cord(self.L[i].pubkey.point)    
                if x == p_x and y == p_y:
                    a = i
            return self.L, a

        
        a = randrange(len(self.L))
        i = 0
        while i < 5:
            if i == pi:
                L.append(pk)
                i+=1
            index = (a+i)%len(self.L)
            x,y = self.get_cord(self.L[index].pubkey.point)
            if x != p_x and y != p_y:
                L.append(self.L[index])
            i+=1

        return L, pi
    
    def decode_pk(self, pk):
        return VerifyingKey.from_pem(pk)
    
    def decode_sk(self, sk):
        return SigningKey.from_pem(sk)
    
    
    def int_to_keys(self, hash_hex) -> tuple[SigningKey, VerifyingKey]:
        # convert hash_hex to integer
        private_key_integer = int(hash_hex, 16)
        try:
            order = self.order_q
            # A direct use of a hash as a private exponent:
            # Ensure the integer form of the hash is less than the curve order.
            private_key_integer = private_key_integer % (order -1) + 1 # Example adjustment

            sk = SigningKey.from_secret_exponent(private_key_integer, curve=self.curve, hashfunc=hashlib.sha256)
            pk = sk.verifying_key
            return sk, pk
        except Exception as e:
            print(f"Error creating SigningKey from hash-derived integer: {e}")
            return None
    
    def string(cls, obj):
        return obj.to_pem(format = "pkcs8").decode("utf-8")
    