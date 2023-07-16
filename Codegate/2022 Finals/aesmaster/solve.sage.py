

# This file was *autogenerated* from the file solve.sage
from sage.all_cmdline import *   # import sage library

_sage_const_2 = Integer(2); _sage_const_29 = Integer(29); _sage_const_0 = Integer(0); _sage_const_8 = Integer(8); _sage_const_1 = Integer(1); _sage_const_0x80 = Integer(0x80); _sage_const_128 = Integer(128); _sage_const_27 = Integer(27); _sage_const_0xFF = Integer(0xFF); _sage_const_0x4C = Integer(0x4C); _sage_const_0x100 = Integer(0x100); _sage_const_4 = Integer(4); _sage_const_3 = Integer(3); _sage_const_0x1B = Integer(0x1B); _sage_const_0x00 = Integer(0x00); _sage_const_0x01 = Integer(0x01); _sage_const_0x02 = Integer(0x02); _sage_const_0x04 = Integer(0x04); _sage_const_0x08 = Integer(0x08); _sage_const_0x10 = Integer(0x10); _sage_const_0x20 = Integer(0x20); _sage_const_0x40 = Integer(0x40); _sage_const_0x36 = Integer(0x36); _sage_const_0x6C = Integer(0x6C); _sage_const_0xD8 = Integer(0xD8); _sage_const_0xAB = Integer(0xAB); _sage_const_0x4D = Integer(0x4D); _sage_const_0x9A = Integer(0x9A); _sage_const_0x2F = Integer(0x2F); _sage_const_0x5E = Integer(0x5E); _sage_const_0xBC = Integer(0xBC); _sage_const_0x63 = Integer(0x63); _sage_const_0xC6 = Integer(0xC6); _sage_const_0x97 = Integer(0x97); _sage_const_0x35 = Integer(0x35); _sage_const_0x6A = Integer(0x6A); _sage_const_0xD4 = Integer(0xD4); _sage_const_0xB3 = Integer(0xB3); _sage_const_0x7D = Integer(0x7D); _sage_const_0xFA = Integer(0xFA); _sage_const_0xEF = Integer(0xEF); _sage_const_0xC5 = Integer(0xC5); _sage_const_0x91 = Integer(0x91); _sage_const_0x39 = Integer(0x39); _sage_const_16 = Integer(16); _sage_const_10 = Integer(10); _sage_const_256 = Integer(256)
F = GF(_sage_const_2 )

def out(x):
    v5 = _sage_const_29 
    v3 = _sage_const_0 
    for i in range(_sage_const_8 ):
        if (x & _sage_const_1 ) == _sage_const_1 :
            v3 ^= v5
        if v5 & _sage_const_0x80  == _sage_const_128 :
            v5 = (_sage_const_2  * v5) ^ _sage_const_27 
        else:
            v5 *= _sage_const_2 
        v5 &= _sage_const_0xFF 
        x >>= _sage_const_1 
    return v3 ^ _sage_const_0x4C 


sbox = []

for i in range(_sage_const_0x100 ):
    sbox.append(out(i))


def sub_bytes(s):
    for i in range(_sage_const_4 ):
        for j in range(_sage_const_4 ):
            s[i][j] = sbox[s[i][j]]


def shift_rows(s):
    s[_sage_const_0 ][_sage_const_1 ], s[_sage_const_1 ][_sage_const_1 ], s[_sage_const_2 ][_sage_const_1 ], s[_sage_const_3 ][_sage_const_1 ] = s[_sage_const_1 ][_sage_const_1 ], s[_sage_const_2 ][_sage_const_1 ], s[_sage_const_3 ][_sage_const_1 ], s[_sage_const_0 ][_sage_const_1 ]
    s[_sage_const_0 ][_sage_const_2 ], s[_sage_const_1 ][_sage_const_2 ], s[_sage_const_2 ][_sage_const_2 ], s[_sage_const_3 ][_sage_const_2 ] = s[_sage_const_2 ][_sage_const_2 ], s[_sage_const_3 ][_sage_const_2 ], s[_sage_const_0 ][_sage_const_2 ], s[_sage_const_1 ][_sage_const_2 ]
    s[_sage_const_0 ][_sage_const_3 ], s[_sage_const_1 ][_sage_const_3 ], s[_sage_const_2 ][_sage_const_3 ], s[_sage_const_3 ][_sage_const_3 ] = s[_sage_const_3 ][_sage_const_3 ], s[_sage_const_0 ][_sage_const_3 ], s[_sage_const_1 ][_sage_const_3 ], s[_sage_const_2 ][_sage_const_3 ]


def add_round_key(s, k):
    for i in range(_sage_const_4 ):
        for j in range(_sage_const_4 ):
            s[i][j] ^= k[i][j]


# learned from https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << _sage_const_1 ) ^ _sage_const_0x1B ) & _sage_const_0xFF ) if (a & _sage_const_0x80 ) else (a << _sage_const_1 )


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[_sage_const_0 ] ^ a[_sage_const_1 ] ^ a[_sage_const_2 ] ^ a[_sage_const_3 ]
    u = a[_sage_const_0 ]
    a[_sage_const_0 ] ^= t ^ xtime(a[_sage_const_0 ] ^ a[_sage_const_1 ])
    a[_sage_const_1 ] ^= t ^ xtime(a[_sage_const_1 ] ^ a[_sage_const_2 ])
    a[_sage_const_2 ] ^= t ^ xtime(a[_sage_const_2 ] ^ a[_sage_const_3 ])
    a[_sage_const_3 ] ^= t ^ xtime(a[_sage_const_3 ] ^ u)


def mix_columns(s):
    for i in range(_sage_const_4 ):
        mix_single_column(s[i])


r_con = [
    _sage_const_0x00 ,
    _sage_const_0x01 ,
    _sage_const_0x02 ,
    _sage_const_0x04 ,
    _sage_const_0x08 ,
    _sage_const_0x10 ,
    _sage_const_0x20 ,
    _sage_const_0x40 ,
    _sage_const_0x80 ,
    _sage_const_0x1B ,
    _sage_const_0x36 ,
    _sage_const_0x6C ,
    _sage_const_0xD8 ,
    _sage_const_0xAB ,
    _sage_const_0x4D ,
    _sage_const_0x9A ,
    _sage_const_0x2F ,
    _sage_const_0x5E ,
    _sage_const_0xBC ,
    _sage_const_0x63 ,
    _sage_const_0xC6 ,
    _sage_const_0x97 ,
    _sage_const_0x35 ,
    _sage_const_0x6A ,
    _sage_const_0xD4 ,
    _sage_const_0xB3 ,
    _sage_const_0x7D ,
    _sage_const_0xFA ,
    _sage_const_0xEF ,
    _sage_const_0xC5 ,
    _sage_const_0x91 ,
    _sage_const_0x39 ,
]


def bytes2matrix(text):
    """Converts a 16-byte array into a 4x4 matrix."""
    return [list(text[i : i + _sage_const_4 ]) for i in range(_sage_const_0 , len(text), _sage_const_4 )]


def matrix2bytes(matrix):
    """Converts a 4x4 matrix into a 16-byte array."""
    return bytes(sum(matrix, []))


def xor_bytes(a, b):
    """Returns a new byte array with the elements xor'ed."""
    return bytes(i ^ j for i, j in zip(a, b))


class AES:
    rounds_by_key_size = {_sage_const_16 : _sage_const_10 }

    def __init__(self, master_key):
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // _sage_const_4 

        i = _sage_const_1 
        while len(key_columns) < (self.n_rounds + _sage_const_1 ) * _sage_const_4 :
            # Copy previous word.
            word = list(key_columns[-_sage_const_1 ])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == _sage_const_0 :
                # Circular shift.
                word.append(word.pop(_sage_const_0 ))
                # Map to S-BOX.
                word = [sbox[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[_sage_const_0 ] ^= r_con[i]
                i += _sage_const_1 

            # XOR with equivalent word from previous iteration.
            word = xor_bytes(bytes(word), key_columns[-iteration_size])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[_sage_const_4  * i : _sage_const_4  * (i + _sage_const_1 )] for i in range(len(key_columns) // _sage_const_4 )]

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == _sage_const_16 

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[_sage_const_0 ])

        for i in range(_sage_const_1 , self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-_sage_const_1 ])
        return matrix2bytes(plain_state)


MAGIC = b"codegate2022{xx}"

coeff = []

for bit_index in range(_sage_const_128 ):
    k = [_sage_const_0  for _ in range(_sage_const_16 )]
    k[bit_index // _sage_const_8 ] = _sage_const_1  << (bit_index % _sage_const_8 )

    aes = AES(k)
    coeff.append(aes.encrypt_block(MAGIC))


def flatten(l):
    assert len(l) == _sage_const_16 
    for x in l:
        assert _sage_const_0  <= x < _sage_const_256 

    ret = []
    for x in l:
        for i in range(_sage_const_8 ):
            if x & (_sage_const_1  << i):
                ret.append(F(_sage_const_1 ))
            else:
                ret.append(F(_sage_const_0 ))
    return ret


mat = matrix([flatten(coeff[i]) for i in range(_sage_const_128 )])
output_vec = vector(flatten([b for b in MAGIC]))

ans = mat.solve_left(output_vec)
print(ans)

print(ans * mat)
print(output_vec)

k = [_sage_const_0  for _ in range(_sage_const_16 )]
for bit_index in range(_sage_const_128 ):
    if ans[bit_index]:
        k[bit_index // _sage_const_8 ] |= _sage_const_1  << (bit_index % _sage_const_8 )

print(bytes(k))
print(bytes(k).hex())
