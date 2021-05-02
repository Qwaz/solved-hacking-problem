import random
import hashlib

N = 168875487862812718103814022843977235420637243601057780595044400667893046269140421123766817420546087076238158376401194506102667350322281734359552897112157094231977097740554793824701009850244904160300597684567190792283984299743604213533036681794114720417437224509607536413793425411636411563321303444740798477587
g = 9797766621314684873895700802803279209044463565243731922466831101232640732633100491228823617617764419367505179450247842283955649007454149170085442756585554871624752266571753841250508572690789992495054848

permitted_users = {
    "get_flag": (0xd14058efb3f49bd1f1c68de447393855e004103d432fa61849f0e5262d0d9e8663c0dfcb877d40ea6de6b78efd064bdd02f6555a90d92a8a5c76b28b9a785fd861348af8a7014f4497a5de5d0d703a24ff9ec9b5c1ff8051e3825a0fc8a433296d31cf0bd5d21b09c8cd7e658f2272744b4d2fb63d4bccff8f921932a2e81813,
                 0xebedd14b5bf7d5fd88eebb057af43803b6f88e42f7ce2a4445fdbbe69a9ad7e7a76b7df4a4e79cefd61ea0c4f426c0261acf5becb5f79cdf916d684667b6b0940b4ac2f885590648fbf2d107707acb38382a95bea9a89fb943a5c1ef6e6d064084f8225eb323f668e2c3174ab7b1dbfce831507b33e413b56a41528b1c850e59)
    };

username = 'get_flag'
salt = permitted_users[username][0]
verifier = permitted_users[username][1]


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


def H(P):
  h = hashlib.sha256()
  h.update(P.encode('ascii'))
  return h.hexdigest()

def tostr(A):
  return hex(A)[2:]

public_client = (modinv(verifier, N) * modinv(g, N)) % N
print(hex(public_client)[2:])
c = (public_client * verifier) % N # 1/g

# random_server = random.randint(2, N-3)
# public_server = pow(g, random_server, N)

residue = int(input('residue? '), 16)
# (public_server + verifier) % N

public_server = residue - verifier
if public_server < 0:
  public_server += N
session_secret = modinv(public_server, N)

# send salt
# send residue

# session_secret = pow(c, random_server, N)
session_key = H(tostr(session_secret))

# proof should be H(tostr(residue) + session_key)
print(H(tostr(residue) + H(tostr(session_secret))))
