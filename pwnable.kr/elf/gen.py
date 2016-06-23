#!/usr/bin/python
import os, random

def gen_binary():
        code = '''
        #define _GNU_SOURCE
        #include <stdio.h>
        '''

        for i in xrange( random.randrange(10000) ):
                code += 'void not_my_flag{0}(){{printf("not a flag!\\n");}}\n'.format(i)

        FLAG = ''
        with open('flag', 'r') as f:
                FLAG = f.read().strip()
	
	code += 'void yes_ur_flag(){{ char flag[]={{"{0}"}}; puts(flag);}}\n'.format(FLAG)

        for i in xrange( random.randrange(10000) ):
                code += 'void not_ur_flag{0}(){{printf("not a flag!\\n");}}\n'.format(i)

        with open('./libflag.c', 'w') as f:
                f.write(code)

        os.system('gcc -o ./libflag.so ./libflag.c -fPIC -shared -ldl 2> /dev/null')

if __name__ == "__main__":
	gen_binary()

