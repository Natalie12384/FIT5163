from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime,  inverse, GCD
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randrange, randint, getrandbits
from Crypto.Hash import SHA256
from sympy import isprime
import Crypto.Random
import math
import sqlite3
import hashlib

class Linkable_Ring:
    #initialise public parameters: q,p,g
    #initialise Ring list L
    # schnorr group is used due to its reliance of cyclic groups
    def __init__(self):
        # prime order q, public
        self.q = getPrime(256) #assume security parameter 256
        # cofactor - multiplicative inverse
        r = getrandbits(2048)
        # prime mod, public
        self.p = r*self.q +1
        assert (self.p - 1) % self.q == 0
        while not isprime(self.p): #its kinda slow, need to ask
            r = getrandbits(2048)
            self.p = r*self.q +1
        h = 1
        # choose random h base
        while pow(h,r,self.p) == 1:
            h = randrange(1,self.p)
        # g = h^r= h^(p-1) mod p -> based on Fermats theorem
        self.g = pow(h,r,self.p) 
        
    
    #add public key to Ring list []
    def add_public_k(self, pk, L):
        L.append(pk)
        return len(L)-1 #index in ring, to be used not stored
    
    # derive sk from IBE sk deterministically?
    # sk: bytes usually, username: string
    def keygen(self, sk, username): # run once for a given member
        sign_sk = SHA256.new(sk+username.encode("UTF-8")).digest()  # Private key 
        x = int.from_bytes(sign_sk, byteorder="big") % self.q
        y = pow(self.g, x, self.p)     # Public key g^x = h^xr mod p
        return (x, y) # to store pk for later pi indexing

    def hash1(self, x):
        return int.from_bytes(hashlib.sha256(x).digest(), 'big') % self.q

    def hash2(self, L): 
        #Encode all public keys as bytes
        Lconcat = b""
        for i in L:
            Lconcat += self.encode_int(i)
        h_val = int.from_bytes(SHA256.new(Lconcat).digest(), 'big')% (self.p)
        return pow(self.g,h_val, self.p) 

    #encodes any integer
    def encode_int(self, x):
        return x.to_bytes((self.p.bit_length()+7)//8, byteorder='big')

    #sign
    # msg: message/vote, pi: index of user, x_pi: sk
    def sign(self, msg, pi, sk, L):

        #tag generation
        x_pk = L[pi] 
        h = self.hash2(L)
        y0 = pow(h, sk, self.p) #tag h^sk

        # generating random values for hashing per pk in L
        r = randrange(0,self.q-1)
        # byte concatenation of z`,z``, pk of L
        cocatz1 = b""
        cocatz2 = b""
        Lconcat = b""
        # challenge
        c_sum = 0
        c_list = [None for i in L]
        #response value?
        s_list = [None for i in L]
        for i in range(0,len(L)):
            s = randrange(1,self.q)
            c = randrange(1,self.q)
            c_list[i] = c
            if i != pi:
                c_sum +=c

            #gi^si * y^ci mod p
            z1 = pow(self.g,s,self.p) *pow(L[i], c, self.p) % self.p
            #gi^si * y^ci
            z2 = pow(h,s, self.p)*pow(y0,c, self.p) % self.p
            if i == pi:
                z1 = pow(self.g,r,self.p)
                z2 = pow(h,r,self.p)
            cocatz1 += self.encode_int(z1)
            cocatz2 += self.encode_int(z2)
            # list of random "sk"
            s_list[i] =s
        for i in L:
            Lconcat += self.encode_int(i)
        # H(L||y0||m||z`..||z``..)
        con = Lconcat+self.encode_int(y0)+msg.encode("UTF-8")+cocatz1+cocatz2
        commitment = self.hash1(Lconcat+self.encode_int(y0)+msg.encode("UTF-8")+cocatz1+cocatz2) %self.q
        c_list[pi] = (commitment - c_sum) % self.q
        s_list[pi] = (r - c_list[pi]*sk) % self.q
        return (y0, s_list, c_list)

    def verify(self,msg, sig, L, db):
        y0 = sig[0]
        s_list = sig[1]
        c_list = sig[2]
        c_sum = 0
        h = self.hash2(L)
        z1_concat = b""
        z2_concat = b""
        Lconcat = b""
        for i in range( len(c_list)):
            c_sum += c_list[i] %self.q
            z1 = pow(self.g, s_list[i], self.p) * pow(L[i], c_list[i], self.p)%self.p
            z1_concat += self.encode_int(z1)
            z2 = pow(h, s_list[i], self.p) *pow(y0, c_list[i], self.p) %self.p
            z2_concat += self.encode_int(z2)
        for i in L:
            Lconcat += self.encode_int(i)
        sigH = self.hash1(Lconcat+self.encode_int(y0)+msg.encode("UTF-8")+z1_concat+z2_concat) %self.q
        return sigH == c_sum 
    
    #assume sig1 is earliest
    def verify_link(self, sig1, sig2, tag, db):
        try:
            db.execute('INSERT INTO link_tags (tag) VALUES (?)', (tag,))
            return True
        except sqlite3.IntegrityError:
            return False

    # https://eprint.iacr.org/2003/186.pdf safe prime generation
    # p = 2q + 1
    def generate_group(self):
        p = 4
        q = 0
        g = 0
        while not isprime(p):
            q = getPrime(256)
            p = 2 * q + 1

        while not (pow(g, q, p) == 1 and pow(g, 2, p) != 1):
            g = randrange(2, p - 1)
        
        return p,q,g

r = Linkable_Ring()
conn = sqlite3.connect('database.db')
c = conn.cursor()
# just in case
c.execute('''DROP TABLE IF EXISTS link_tags''')
c.execute('''CREATE TABLE IF NOT EXISTS link_tags (
            tag TEXT PRIMARY KEY
          )''')
conn.commit()
conn.close()
L = []
sk,pk = r.keygen(b'hello',"hello")
pi = r.add_public_k(pk, L)
sig = r.sign("hello",pi,  sk, L )
conn = sqlite3.connect('database.db')
c = conn.cursor()
v = r.verify("hello",sig, L, c)
print(v)
conn.commit()
conn.close()