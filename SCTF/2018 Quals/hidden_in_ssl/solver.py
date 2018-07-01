import binascii
import os

STREAMS_DIR = 'streams'
RESULT_DIR = 'results'

for filename in sorted(os.listdir(STREAMS_DIR)):
    with open(os.path.join(STREAMS_DIR, filename), 'rb') as f:
        content = f.read()
    lines = content.split('\n')

    result = open(os.path.join(RESULT_DIR, filename+'.jpg'), 'wb')
    try:
        i = 0
        while True:
            s = (lines[i+1][19:58] + lines[i+2][10:43]).replace(' ', '')
            include = int(lines[i+12].strip().split()[2])
            if include == 1:
                result.write(binascii.unhexlify(s))
            i += 13
    except Exception as e:
        pass

    result.close()
