from pwn import *
from base64 import b64encode

code = '''
' '?y=y
x?' '=x
_?_='~'
(x:c)??(y:d)=x?y:c??d
x??y=x++y
""#[]=[(0,"")]
x#y=[(c+1,a:d)|a:b<-[x],a/='~',(c,d)<-b#y]++[c|a:b<-[y],c<-x??a#b]
g a=snd$minimum$(#)""=<<permutations a
'''.strip()

p = remote('code-golf.ctfcompetition.com', 1337)
p.sendline(b64encode(code))

p.interactive()
