from pycocks.cocks import CocksPKG
from pycocks.cocks import Cocks

cocks_pkg = CocksPKG()
class IBEServer:
    def __init__(self):
        self.cocks_pkg = CocksPKG()
        self.cocks = Cocks(self.cocks_pkg.n)

    def client_key_pair_gen(self, id):
        pk, sk = self.cocks_pkg.keygen(id)
        return pk, sk

    def encrypt(self, pk, message):
        c = self.cocks.encrypt(message, pk)
        return c
    
    def decrypt(self, sk, c):
        m = self.cocks.decrypt(c, pk, sk)
        return m

        