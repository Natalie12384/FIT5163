from pycocks.cocks import CocksPKG
from pycocks.cocks import Cocks

cocks_pkg = CocksPKG()
class IBEServer:
    def __init__(self):
        self.cocks_pkg = CocksPKG()
        self.cocks = Cocks(self.cocks_pkg.n)

    def client_key_pair_gen(self, id):
        sk, pk = self.cocks_pkg.extract(id)
        return int(pk), int(sk)

    def encrypt(self, pk, message):
        c = self.cocks.encrypt(message, pk)
        return c
    
    def decrypt(self, sk, c):
        m = self.cocks.decrypt(c, pk, sk)
        return m

if __name__ == "__main__":
    server = IBEServer()
    pk, sk = server.client_key_pair_gen("alice@example.com")
    print(pk)
