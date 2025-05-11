from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, getRandomRange, inverse, GCD
from Crypto.Random import get_random_bytes, random
from Crypto.Hash import SHA256
import  Crypto.Random

import sys
from sagemath import *
import math

class Linkable_Ring:
    #initialise public parameters: q,p,g
    #initialise Ring list L
    def __init(self):
        self.q = getPrime(256)
        self.p = getPrime(1024)
        self.r = (self.p-1)//self.q
        self.h = 1
        while pow(self.h,self.r,self.p) == 1:
            self.h = getRandomRange(1,self.p)
        self.g = pow(self.h,self.r,self.p)
        self.L = []
    
    #add public key to Ring list
    def add_public_k(self, pk):
        self.L.append(pk)
        return len(self.L)-1

    def keygen(self): # run once for a given member
        x = getRandomRange(1, self.q)  # Private key
        y = pow(self.g, x, self.p)     # Public key
        return (x, y)

    def hash1(self, x):
        return int.from_bytes(SHA256.new(x).digest(), 'big') % self.q

    def hash2(self): 
        #Encode all public keys as bytes
        L = self.L
        Lconcat = ""
        for i in L:
            Lconcat += self.encode_int(i)
        h_val = int.from_bytes(SHA256.new(Lconcat).digest(), 'big')
        return pow(self.g,h_val% self.q, self.p) 

    def encode_int(self, x):
        return x.to_bytes(32, byteorder='big')

    def sign(self, msg, pi):
        u = random.randint(1,self.q)
        h = self.hash2()
        x_pi = self.L[pi] ##placeholder
        y0 = h**x_pi
        cocatz1 = b""
        cocatz2 = b""
        Lconcat = b""
        c_sum = 0
        c_list = [None for i in L]
        s_list = [None for i in L]
        for i in range(0,len(L)):
            s = getRandomRange(1,self.q)
            c = getRandomRange(1,self.q)
            if i != pi:
                c_list[i] = c
                c_sum +=c
            z1 = self.g**s*L[i]**c
            z2 = h**s*y0**c
            if i == pi:
                z1 = self.g**self.r
                z2 = h**self.r
            cocatz1 += z1.encode('UTF-8')
            cocatz2 += z2.encode('UTF-8')
        s_list[pi] = self.r - c_list[pi]*x_pi
        for i in self.L:
            Lconcat += self.encode_int(i)
        # H(L||y0||m||z`..||z``..)
        commitment = self.hash1(Lconcat+self.encode_int(y0)+msg.encode("UTF-8")+cocatz1+cocatz2)
        c_list[pi] = commitment - c_sum % self.q
        return (y0, s_list, c_list)

    def verify(self,msg, sig):
        y0 = sig[0]
        s_list = sig[1]
        c_list = sig[2]
        c_sum = 0
        s_concat = b""
        Lconcat = b""
        for i in c_list:
            c_sum += i 
        c_sum = c_sum%self.q
        for i in s_list:
            s_concat += self.encode_int(i)
        for i in self.L:
            Lconcat += self.encode_int(i)
        sigH = self.hash1(Lconcat+y0+msg.encode("UTF-8")+s_concat)
        return sigH == c_sum
    
    #assume sig1 is earliest
    def verify_link(self, sig1, sig2,L, msg):

        return
print()