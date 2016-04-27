Tonnerre Writeup
==============

## 1. SQL Injection
```SQL
' union (select table_name from information_schema.tables LIMIT 40,1) -- -
' union (select table_name from information_schema.tables LIMIT 41,1) -- -
```
First, we can find table names `users` and `admin_users` with trivial SQL injection. `admin_users` tables is used for web server and `users` table is used for terminal login.

```SQL
' union (select column_name from information_schema.columns where table_name='admin_users' limit 0,1) -- -
```
We can even extract column names for each table with the query above.

```
[users]
user
salt
verifier

[admin_users]
user
pass
```
This is the table structure. There is only one user in `users` table.

* user=get_flag
* salt=d14058efb3f49bd1f1c68de447393855e004103d432fa61849f0e5262d0d9e8663c0dfcb877d40ea6de6b78efd064bdd02f6555a90d92a8a5c76b28b9a785fd861348af8a7014f4497a5de5d0d703a24ff9ec9b5c1ff8051e3825a0fc8a433296d31cf0bd5d21b09c8cd7e658f2272744b4d2fb63d4bccff8f921932a2e81813
* verifier=ebedd14b5bf7d5fd88eebb057af43803b6f88e42f7ce2a4445fdbbe69a9ad7e7a76b7df4a4e79cefd61ea0c4f426c0261acf5becb5f79cdf916d684667b6b0940b4ac2f885590648fbf2d107707acb38382a95bea9a89fb943a5c1ef6e6d064084f8225eb323f668e2c3174ab7b1dbfce831507b33e413b56a41528b1c850e59

---

## 2. public_server.py
1. Get `username` and compare it
2. Get `public_client` as a hex value
3. `c = public_client * verifier`
4. Check `c not in [N-g, N-1, 0, 1, g]`
5. `random_server = random.randint(2, N-3)`
6. `public_server = pow(g, random_server, N)`
7. `residue = (public_server + verifier) % N`
8. Print `salt`, `residue`
9. `session_secret = pow(c, random_server, N)`
10. `session_key = SHA256(tostr(session_secret))`
11. Get `proof` and compare with `SHA256(tostr(residue) + session_key)`. If match, print *flag*.

---

## 3. How to solve
Let `P = public_client`, `V = verifier`, `R = random_server`.

### Observation
- `salt` is useless
- P can be controlled, N, g, V is known, R is unknown
- `residue = (g**R + V) % N` is known $\iff$ `(g**R) % N` is known
- We should calculate `((P*V)**R) % N`

### Modular Inverse
If we know a prime number $N$ and an integer $a$, we can calculate $a^{-1}$ such that $a \times a^{-1} \equiv 1 ~ mod ~ N$.

### Solve
#### First Attempt
Let $P = V^{-1}g$. Then $(PV)^R \equiv g ^ R ~ mod ~ N$. Then we can calculate it with the residue. However, `c` becomes `g` and this solution cannot pass number 4.

#### Second Attempt
Let $P = V^{-1}g^{-1}$. Then $(PV) ^ R \equiv (g^{-1}) ^ R ~ mod ~ N$. We can calculate this value with the modular inverse of $g^R ~ mod ~ N$. Yay!