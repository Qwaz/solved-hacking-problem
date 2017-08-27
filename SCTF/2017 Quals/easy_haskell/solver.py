import os
import subprocess

charset = '_{}?ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz'
target = '=ze=/<fQCGSNVzfDnlk$&?N3oxQp)K/CVzpznK?NeYPx0sz5'

found = ''
matched = 0


def check(s):
    os.system('ln -s ./EasyHaskell {}'.format(s))
    result = subprocess.check_output('./' + s).strip()[1:-1]
    os.system('rm {}'.format(s))
    return result

while True:
    for c1 in charset:
        r = check(found+c1)
        if r == target:
            print '[+] Flag Found: {}'.format(found+c1)
            exit(0)
        if r[matched] == target[matched]:
            print '[*] Trying {} - {}'.format(found+c1, r)
            flag = False
            for c2 in charset:
                if matched % 4 == 0:
                    if check(found+c1+c2)[matched:matched+2] == target[matched:matched+2]:
                        flag = True
                        found += c1
                        matched += 1
                        break
                else:
                    if check(found+c1+c2)[matched:matched+3] == target[matched:matched+3]:
                        flag = True
                        found += c1+c2
                        matched += 3
                        break
            if flag:
                print '[+] OK! - {}'.format(found)
                break
