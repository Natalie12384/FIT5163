from pycocks.cocks import CocksPKG
from pycocks.cocks import Cocks

cocks_pkg = CocksPKG()
class IBEServer:
    def __init__(self):
        self.cocks_pkg = CocksPKG()
        self.cocks = Cocks(self.cocks_pkg.n)

    def client_key_pair_gen(self, id):
        sk, hashed_id = self.cocks_pkg.extract(id)
        return sk, hashed_id

    def encrypt(self, pk, message):
        c = self.cocks.encrypt(message, pk)
        return c
    
    def decrypt(self, c,sk, id):
        m = self.cocks.decrypt(c,  sk,id)
        return m
    
