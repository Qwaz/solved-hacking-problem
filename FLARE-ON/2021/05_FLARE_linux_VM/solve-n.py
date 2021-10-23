def sxor(s1, s2):
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    return bytes(bytearray(a ^ b for a, b in zip(s1, s2)))


with open("Fixed/natillas.txt", "rb") as f:
    natillas = f.read()

with open("Fixed/nutella.txt", "rb") as f:
    nutella = f.read()

with open("Fixed/nachos.txt", "rb") as f:
    nachos = f.read()

key = sxor(nutella, b"The 6th byte of the password is: 0x36\n")

print(sxor(key, natillas))
print(sxor(key, nutella))
print(sxor(key, nachos))

key = sxor(natillas, b"Do you know natillas? In Spain, this term refers to a custard dish made with milk and ")

print(sxor(key, natillas))
print(sxor(key, nutella))
print(sxor(key, nachos))

key = sxor(nachos, b"In the FLARE team we really like Felix Delastelle algorithms, specially the one which")

print(sxor(key, natillas))
print(sxor(key, nutella))
print(sxor(key, nachos))
