class Zp:
    def __init__(self,p,value):
        self.p = p
        self.value = value % p

    def __add__(self, other):
        return Zp(self.value + other.value, self.p)

    def __sub__(self, other):
        return Zp(self.value - other.value, self.p)

    def __mul__(self, other):
        return Zp(self.value * other.value, self.p)

    def __pow__(self, exponent):
        return Zp(pow(self.value, exponent, self.p), self.p)

    def inverse(self):
        return Zp(pow(self.value, -1, self.p), self.p)
