p = 16857450949524777441941817393974784044780411511252189319

A = 16857450949524777441941817393974784044780411507861094535
B = 77986137112576

P = (5732560139258194764535999929325388041568732716579308775, 14532336890195013837874850588152996214121327870156054248)
Q = (2609506039090139098835068603396546214836589143940493046, 8637771092812212464887027788957801177574860926032421582)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def addPoint(P, Q):
    if P == (0, 0) or Q == (0, 0):
        return (P[0]+Q[0], P[1]+Q[1])
    
    x_1, y_1, x_2, y_2 = P[0], P[1], Q[0], Q[1]
 
    if (x_1, y_1) == (x_2, y_2):
        if y_1 == 0:
            return (0, 0)
 
        # slope of the tangent line
        m = (3 * x_1 * x_1 + A) * modinv(2 * y_1, p)
    else:
        if x_1 == x_2:
            return (0, 0)
 
        # slope of the secant line
        m = (y_2 - y_1) * modinv((x_2 - x_1 + p) % p, p)
 
    x_3 = (m*m - x_2 - x_1) % p
    y_3 = (m*(x_1 - x_3) - y_1) % p
 
    return (x_3, y_3)

def mulPoint(n, P):
    r = (0, 0)
    t = P
    while n:
        if n & 1:
            r = addPoint(r, t)
        t = addPoint(t, t)
        n >>= 1
    return r

