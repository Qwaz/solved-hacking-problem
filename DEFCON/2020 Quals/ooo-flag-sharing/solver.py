from ast import literal_eval
from pwn import *
import fuckpy3
import string

USERNAME = "Qwaz"
PROC = None

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


def reset():
    global PROC
    if PROC is not None:
        PROC.close()
    PROC = remote("ooo-flag-sharing.challenges.ooo", 5000)
    PROC.recvuntil("Username: ")
    PROC.sendline(USERNAME)


def wait_menu(choice):
    PROC.recvuntil("Choice: ")
    PROC.sendline(str(choice))


def share_user(secret):
    wait_menu(1)
    PROC.recvuntil("secret to share: ")
    PROC.sendline(secret)
    PROC.recvuntil("secret's ID is: ")
    secret_id = PROC.recvline().strip()
    PROC.recvuntil("Number of shares to make: ")
    PROC.sendilne("123")
    try:
        PROC.recvuntil("Your shares are: ")
    except EOFError:
        reset()
        return (secret_id, None)
    shares = literal_eval(PROC.recvline().strip().str())

    return (secret_id, shares)


def share_flag():
    wait_menu(3)
    PROC.recvuntil("secret's ID is: ")
    secret_id = PROC.recvline().strip()
    PROC.recvuntil("Your shares are: ")
    shares = literal_eval(PROC.recvline().strip().str())

    return (secret_id, shares)


def redeem_user(secret_id, shares):
    wait_menu(2)
    PROC.recvuntil("secret's ID: ")
    PROC.sendline(secret_id)
    PROC.recvuntil("your shares of the secret: ")
    PROC.sendline(str(shares))
    try:
        PROC.recvuntil("Your secret is: ", timeout=1)
    except EOFError:
        reset()
        return None
    secret_bytes = literal_eval(PROC.recvuntil("What do, ", drop=True).str())
    secret_int = int.from_bytes(secret_bytes, byteorder='little')

    return secret_int


def redeem_flag(secret_id, shares):
    wait_menu(4)
    PROC.recvuntil("secret's ID: ")
    PROC.sendline(secret_id)
    PROC.recvuntil("your shares of the secret: ")
    PROC.sendline(str(shares))
    try:
        return b"Congrats!" in PROC.recvuntil("What do, ")
    except EOFError:
        reset()
        return None


reset()

(flag_secret_id, flag_pub_share) = share_flag()

print(flag_secret_id)
print(flag_pub_share)

user_rows = [share[0] for share in flag_pub_share]

print(user_rows)

# Step 1: row number recovery
for secret_row_1 in range(100):
    if secret_row_1 in user_rows:
        continue
    if redeem_user(flag_secret_id, flag_pub_share + [(secret_row_1, 0)]) is None:
        break

log.success(f"Secret row 1: {secret_row_1}")

reset()

for secret_row_2 in range(100):
    if secret_row_2 == secret_row_1 or secret_row_2 in user_rows:
        continue
    if redeem_flag(flag_secret_id, flag_pub_share + [(secret_row_2, 0)]) is None:
        break

log.success(f"Secret row 2: {secret_row_2}")

# Step 2: leak inv matrix
reset()

inv = {}
target_rows = user_rows + [secret_row_1, secret_row_2]

for i in range(5):
    # here, we assume nothing is lost due to \x00 stripping
    inv[target_rows[i]] = redeem_user(flag_secret_id, [(target_rows[idx], 1 if i == idx else 0) for idx in range(5)])

print(inv)

# Step 3: finding p
step = inv[secret_row_1]
prev = step
i = 1

while True:
    i += 1
    now = redeem_user(flag_secret_id, [
        (user_rows[0], 0),
        (user_rows[1], 0),
        (user_rows[2], 0),
        (secret_row_1, i),
        (secret_row_2, 0),
    ])
    if now != prev + step:
        p = prev + step - now
        break
    prev = now

log.success(f"p: {p}")
assert p == 95820804521871446624646154398560990164494336030962272285033480112778980081147, "P recovery failed!"

# Step 4: extract flag
one = modinv(inv[user_rows[0]], p)

prefix = int.from_bytes(b"OOO", byteorder="little")
known = "OOO{"

guess_order = [c for c in "_-}eothasinrdluymwfgcbpkvjqxz0123456789EOTHASINRDLUYMWFGCBPKVJQXZ"]
for c in string.printable:
    if c not in guess_order:
        guess_order.append(c)

while known[-1] != "}":
    reset()
    log.info(f"Flag status: {known}")
    offset = (
        int.from_bytes(b"OOO{", byteorder="little") * (256 ** (len(known) - 3))
        - int.from_bytes(known.bytes(), byteorder="little")
    )
    for guess in guess_order:
        if redeem_flag(flag_secret_id, [
            (flag_pub_share[0][0], (flag_pub_share[0][1] + one * (offset - ord(guess) * (256 ** len(known)))) % p),
            flag_pub_share[1],
            flag_pub_share[2],
        ]):
            known = known + guess
            break

# OOO{ooo_c4nt_ke3p_secr3ts!}
log.success(f"Flag: {known}")
