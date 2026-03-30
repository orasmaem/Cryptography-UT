#!/usr/bin/env python3
import os, sys       # do not use any other imports/libraries
# spent basicallly a day on the homework, but deep concentraded work was about 3 hours.

def bi(b):
    # b - bytes to encode as an integer (big-endian)
    value = 0
    for byte in b:
        value = (value << 8) | byte
    return value

def ib(i, length):
    # i - an integer to encode as bytes (big-endian)
    # length - specifies in how many bytes the integer should be encoded
    out = bytearray(length)
    last_index = length - 1
    while last_index >= 0:
        out[last_index] = i & 0xff
        i >>= 8
        last_index -= 1
    return bytes(out)

def encrypt(pfile, kfile, cfile):
    plain = open(pfile, 'rb').read()
    key = os.urandom(len(plain))

    pi = bi(plain)
    ki = bi(key)
    ci = pi ^ ki

    cipher = ib(ci, len(plain))
    open(kfile, 'wb').write(key)
    open(cfile, 'wb').write(cipher)

def decrypt(cfile, kfile, pfile):
    c = open(cfile, 'rb').read()
    k = open(kfile, 'rb').read()

    ci = bi(c)
    ki = bi(k)
    pi = ci ^ ki

    p = ib(pi, len(c))
    open(pfile, 'wb').write(p)

def usage():
    print("Usage:")
    print("encrypt <plaintext file> <output key file> <ciphertext output file>")
    print("decrypt <ciphertext file> <key file> <plaintext output file>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()

