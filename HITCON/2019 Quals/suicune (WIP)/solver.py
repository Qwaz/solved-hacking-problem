import string
import sys

N=0x5851F42D4C957F2DL
mask=2**64-1
mask32=2**32-1

def swap(arr, a, b):
  arr[a], arr[b] = arr[b], arr[a]

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

class Random:
  def __init__(self, seed):
    self.state = ((seed * N&mask)+N+1)&mask
  def generate(self):
    a=self.state
    data=ror(((a ^ (a >> 18)) >> 27)&mask32, a >> 59, 32)
    self.state=((0x5851F42D4C957F2D * self.state&mask)+1)&mask
    return data

input=bytearray('flag{cuxnvyrsuy}')
keyval=34895
R=Random(keyval);
round = 0;

for round in range(16):
  state = range(256)
  curState = state[:]
  for v46 in range(len(state), 1, -1):
    r=(mask32+1-v46)%v46
    if r:
      r=mask32+1-r
      while True:
        v53=R.generate()
        if v53<r:
          break
    else:
      v53 = R.generate()
    swap(curState, (v53 % v46), v46 - 1)
  sliced = curState[:len(input)]
  r64 = R.generate();
  r64 |= R.generate() << 32
  sliced=sorted(sliced, key=lambda x: -x)
  input = [x^y for x, y in zip(sliced, input)]
  input = input[::-1]
input=str(bytearray(input))
print input.encode('hex')

# orig='04dd5a70faea88b76e4733d0fa346b086e2c0efd7d2815e3b6ca118ab945719970642b2929b18a71b28d87855796e344d8'.decode('hex')
orig=input

orig=list(bytearray(orig))
lol = [x<=128 for x in range(256)]

slices=[None]*16
# for keyval in range(0, 65536):
for keyval in [keyval]:
  input=orig[:]
  R=Random(keyval)
  if keyval & 0xff == 0:
    print keyval
  for round in range(16):
    state = range(256)
    curState = state[:]
    for v46 in range(256, 1, -1):
      r=(mask32+1-v46)%v46
      if r:
        r=mask32+1-r
        while True:
          v53 = R.generate()
          if v53<r:
            break
          print keyval, '!'
      else:
        v53 = R.generate()
      # print '0x%x'%(v53%v46),
      curState[v53%v46],curState[v46-1]=curState[v46-1],curState[v53%v46]
      # swap(curState, (v53 % v46), v46 - 1)
    sliced = curState[:len(input)]
    r64 = R.generate();
    r64 |= R.generate() << 32
    slices[round]=sorted(sliced, key=lambda x: -x)
  for round in range(16):
    input = input[::-1]
    input = [x^y for x, y in zip(slices[15-round], input)]
    # print input
  input=str(bytearray(input))
  if 1:
    print input
    # break
    # open('payload','wb').write(input)
