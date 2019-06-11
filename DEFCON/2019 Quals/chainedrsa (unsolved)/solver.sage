def partial_p(p0, kbits, n):
    for i in range(2 ** (1025 - kbits)):
        p = (2^kbits) * i + p0
        g = gcd(n, p)
        if 1 < g < n:
            return ZZ(g)


def find_p(d0, kbits, e, n):
    X = var('X')

    for k in xrange(1, 128 + 1):
        print 'start %d' % k
        # results = solve_mod([e*d0*X - k*X*(n-X+1) + k*n == X], 2^kbits)
        results = solve_mod([k * X * X + (e * d0 - k - 1 - k * n) * X + k * n == 0], 2^kbits)
        print 'eq solved; k: %d, len(results): %d' % (k, len(results))
        for x in results:
            p0 = ZZ(x[0])
            p = partial_p(p0, kbits, n)
            if p:
                return p


if __name__ == '__main__':
    import pickle

    if os.path.exists('data'):
        with open('data', 'rb') as f:
            history = pickle.load(f)
    else:
        history = {}

    n = 25330277747231756612769106496057245992336516703193398598113285501808751123531810008263092666116087694574704513335691451213061076455622130777981225676578972132193687810137645606455702987230297009408565595955446311192636788249979110121084574819345845512891580302166698423734475816152658149032751888425134019401447334236444071613598670275228754333869157750670342310818780637771115762630286641217639628324837594787124073510215546327740265997751837492250814514585919200051465061456160048304997000330265152003909507503511295786157427777121052299523450609799942615682467086438071517483760751348980574400446452710966499951809
    e = 65537
    d0 = 0x697128A24588F88D9BCF6F9A11BF26B3B12B07BA7B858EFDEAD49F933B127CAF5921D45E292979C3815041F9118054B8437A3A0E6764A9C66542A6360A9C89342B89D565CB6944C03EDE1033A5662DBC5B49D7A06E275476C3F885506D27FC10C54C78A8E46F7FC625AC2DC93B22A6B1CB17A9B463BA456E2AC196231E9435
    kbits = 1019

    for N in history:
        print "Trying N = %d" % N
        p = find_p(d0, kbits, e, N)
        if p is not None:
            print "found p: %d" % p
            q = N // p
            print inverse_mod(e, (p-1)*(q-1))
