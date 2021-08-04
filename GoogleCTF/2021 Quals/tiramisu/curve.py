import collections

# Taken from: https://gist.github.com/bellbind/1414867/03b4b2dd79b41e65e51716076e5e2b0171628a10
Coord = collections.namedtuple("Coord", ["x", "y"])


class EC:
    def __init__(self, a, b, q):
        """elliptic curve as: (y**2 = x**3 + a * x + b) mod q
        - a, b: params of curve formula
        - q: prime number
        """
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2)) % q != 0
        self.a = a
        self.b = b
        self.q = q
        # just as unique ZERO value representation for "add": (not on curve)
        self.zero = Coord(0, 0)
        pass

    def add(self, p1, p2):
        if p1 == self.zero:
            return p2
        if p2 == self.zero:
            return p1
        if p1.x == p2.x and p1.y != p2.y:
            # p1 + -p1 == 0
            return self.zero
        if p1.x == p2.x:
            # p1 + p1: use tangent line of p1 as (p1,p1) line
            l = (3 * p1.x * p1.x + self.a) * pow(2 * p1.y, -1, self.q) % self.q
            pass
        else:
            l = (p2.y - p1.y) * pow(p2.x - p1.x, -1, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Coord(x, y)

    def mul(self, p, n):
        ret = self.zero
        for bit in bin(n)[2:]:
            ret = self.add(ret, ret)
            if bit == '1':
                ret = self.add(ret, p)
        return ret
