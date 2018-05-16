import os
import re
import subprocess

TEST_FILE = 'test.v'

VERIFY_SECRET = '44' * 16
AUTH_SECRET = '00' * 16
PORT = 8080

VERIFY_ARG = [
    './smcauth', 'verify', '--netlist', TEST_FILE,
    '-l', '127.0.0.1:%d' % PORT,
    '--secret', VERIFY_SECRET
]

AUTH_ARG = [
    'strace', '-f', '-x',
    '-e', 'trace=network', '-s', '100000', '--',
    './smcauth', 'auth', '--netlist', TEST_FILE,
    '-v', '127.0.0.1:%d' % PORT,
    '--secret', AUTH_SECRET
]

SEND_PATTERN = re.compile(r'^\[pid +\d+\] sendto\(\d+, "([^"]+)", [^,]+, [^,]+, [^,]+, [^,]+\) = \d+$')
RECV_PATTERN = re.compile(r'^\[pid +\d+\] recvfrom\(\d+, "([^"]+)", [^,]+, [^,]+, [^,]+, [^,]+\) = \d+$')

verifier = subprocess.Popen(VERIFY_ARG)
author = subprocess.Popen(AUTH_ARG, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

(out, err) = author.communicate()
print out

counter = 0

dump_directory = os.path.join('dump', str(author.pid))
if not os.path.exists(dump_directory):
    os.makedirs(dump_directory)

def log_result(filename, content):
    global counter
    with open(os.path.join(dump_directory, filename), 'wb') as f:
        f.write(content)
    counter += 1

log_result('raw', err)

for line in err.split('\n'):
    result = SEND_PATTERN.match(line)
    if result is not None:
        content = result.group(1).decode('string_escape')
        log_result('%02d-send' % counter, content)
        continue

    result = RECV_PATTERN.match(line)
    if result is not None:
        content = result.group(1).decode('string_escape')
        log_result('%02d-recv' % counter, content)
        continue

verifier.kill()
