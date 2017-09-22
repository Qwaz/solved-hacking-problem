def hashcode(s):
    ret = 0
    for c in s:
        ret = ret * 31 + ord(c)
    return ret

s = 'Pas$ion'
print 'Target = %d' % hashcode(s)

my = 'ParCion'
print 'Hashcode = %d' % hashcode(my)
