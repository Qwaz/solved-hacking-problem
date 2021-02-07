import functools as f
import gmpy2

aa = 0
while True:
    a = str(aa)
    b = str(aa + 1)
    c = str(aa + 2)
    d = str(aa + 3)

    if int(a)==int(b)-1==int(c)-2==int(d)+-3:
        n=int(''.join(map(str,(a,b,c,d))))
        if f.reduce(lambda x,y:x*(int(''.join(map(str,(a,b,c,d))))%y),range(1,int(int(''.join(map(str,(a,b,c,d))))**.5)+1)):
            print('HCL8{The_m4gic_number_is_%d}'%(int(a)**int(b)*int(c)**int(d)))
        if gmpy2.is_prime(n):
            print('HCL8{The_m4gic_number_is_%d}'%(int(a)**int(b)*int(c)**int(d)))

    aa += 1
