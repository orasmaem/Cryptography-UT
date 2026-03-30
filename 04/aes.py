#!/usr/bin/env python3

import time, os, sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python3-pycryptodome
sys.path = sys.path[1:] # removes current directory from aes.py search path
from Cryptodome.Cipher import AES          # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ecb-mode
from Cryptodome.Util.strxor import strxor  # https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#crypto-util-strxor-module
from hashlib import pbkdf2_hmac
import hashlib, hmac # do not use any other imports/libraries

# took 15 hours

#==== ASN1 encoder start ====
# put your DER encoder functions here

#!/usr/bin/env python3
import sys   # do not use any other imports/libraries

# took about 15-20 hours


def asn1_len(value_bytes):
    # helper function - should be used in other functions to calculate length octet(s)
    # value_bytes - bytes containing TLV value byte(s)
    # returns length (L) byte(s) for TLV
    length = len(value_bytes)

    #only one byte is needed to show the length
    if length < 128:
        return bytes([length])
    


    bits_needed = length.bit_length()
    bytes_needed = (bits_needed + 7) >> 3

    encoded_length = length.to_bytes(bytes_needed, 'big')

    length_of_length = bytes([0x80 | bytes_needed])
    
    length_field = length_of_length + encoded_length
    return length_field

def asn1_boolean(boolean):
    # BOOLEAN encoder has been implemented for you
    if boolean:
        boolean = b'\xff'
    else:
        boolean = b'\x00'
    return bytes([0x01]) + asn1_len(boolean) + boolean

def asn1_null():
    # returns DER encoding of NULL
    return bytes([0x05, 0x00])

def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER
    if i == 0:
        value = b"\x00"

    else:
        bytes_needed = (i.bit_length() + 7) >> 3
        value = i.to_bytes(bytes_needed, "big", signed=False)
        #print(value)
        if value[0] & 0x80:
            value = b"\x00" + value


    return bytes([0x02]) + asn1_len(value) + value
    

def asn1_bitstring(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    bits = len(bitstr)
    if bits == 0:
        value = b"\x00"
    padding_bits=(8-(bits%8)) % 8
    padded_bitstring = bitstr + "0"*padding_bits

    bytevalues = []
    for i in range(0, len(padded_bitstring), 8):
        byte = 0
        for bit in padded_bitstring[i:i+8]:
            byte <<= 1
            if bit == "1":
                byte |= 1
        bytevalues.append(byte)
    octets = bytes(bytevalues)


    value = bytes([padding_bits]) + octets

    return bytes([0x03]) +asn1_len(value) + value

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    return bytes([0x04]) + asn1_len(octets) + octets

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    first_two_nodes = oid[0]*40 + oid[1]
    valuebytes = []

    for node in [first_two_nodes] + oid[2:]:
        seven_bits = []
        while node > 0:
            seven_bits.append(node & 0x7F)
            node >>= 7
        
        seven_bits.reverse()

        for i in range(len(seven_bits)-1):
            seven_bits[i] |= 0x80
        valuebytes.extend(seven_bits)
    value = bytes(valuebytes)

    return bytes([0x06]) + asn1_len(value) + value
def asn1_sequence(der):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE



    return bytes([0x30]) + asn1_len(der) + der

def asn1_set(der):
    # der - DER bytes to encapsulate into set
    # returns DER encoding of SET
    return bytes([0x31]) + asn1_len(der) + der

def asn1_utf8string(utf8bytes):
    # utf8bytes - bytes containing UTF-8 encoded unicode characters (e.g., b"F\xc5\x8d\xc5\x8d")
    # returns DER encoding of UTF8String
    return bytes([0x0c]) + asn1_len(utf8bytes) + utf8bytes

def asn1_utctime(time):
    # time - bytes containing timestamp in UTCTime format (e.g., b"121229010100Z")
    # returns DER encoding of UTCTime
    return bytes([0x17]) + asn1_len(time) + time

def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type
    tag = bytes([0xA0 + tag])
    return tag + asn1_len(der) + der

# figure out what to put in '...' by looking on ASN.1 structure required (see slides)
asn1 = asn1_tag_explicit(
    asn1_sequence(
        asn1_set(
            asn1_integer(5) +
            asn1_tag_explicit(asn1_integer(200), 2) +
            asn1_tag_explicit(asn1_integer(65407), 11)
        ) +
        asn1_boolean(True) +
        asn1_bitstring("011") +
        asn1_octetstring(b"\x00\x01\x02" + b"\x02" * 48) +
        asn1_null() +
        asn1_objectidentifier([1, 2, 840, 113549, 1]) +
        asn1_utf8string(b"hello.") +
        asn1_utctime(b"250223010900Z")
    ),
    0
)
open(sys.argv[1], 'wb').write(asn1)




#==== ASN1 encoder end ====


# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():

    # measure time for performing 10000 iterations
    start = time.time()
    pbkdf2_hmac('sha1', b'benchmark', b'\x00' * 8, 10000, 48)
    stop = time.time()
    took = stop - start

    # extrapolate to 1 second
    iter = int(10000 / took) if took > 0 else 10000

    print("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter))

    return iter # returns number of iterations that can be performed in 1 second


def encrypt(pfile, cfile):

    # benchmarking
    iter = benchmark()

    # asking for a password
    password = input("[?] Enter password: ").encode()

    # derieving keys
    salt = os.urandom(8)
    keymat = pbkdf2_hmac('sha1', password, salt, iter, 48)
    key_aes = keymat[:16]
    key_hmac = keymat[16:48]

    # reading plaintext
    f = open(pfile, 'rb')
    plaintext = f.read()
    f.close()

    # padding plaintext
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len

    # encrypting padded plaintext
    iv = os.urandom(16)
    cipher = AES.new(key_aes, AES.MODE_ECB)
    iv_current = iv
    out = []
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        enc = cipher.encrypt(strxor(block, iv_current))
        out.append(enc)
        iv_current = enc
    ciphertext = b''.join(out)

    # MAC calculation (iv+ciphertext)
    mac = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()

    # constructing DER header
    kdfinfo = asn1_sequence(
        asn1_octetstring(salt) +
        asn1_integer(iter) +
        asn1_integer(48)
    )
    aesinfo = asn1_sequence(
        asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 1, 2]) +
        asn1_octetstring(iv)
    )
    hmacinfo = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]) +
            asn1_null()
        ) +
        asn1_octetstring(mac)
    )
    header = asn1_sequence(kdfinfo + aesinfo + hmacinfo)

    # writing DER header and ciphertext to file
    f = open(cfile, 'wb')
    f.write(header + ciphertext)
    f.close()
def decrypt(cfile, pfile):

    # reading DER header and ciphertext
    f = open(cfile, 'rb')
    contents = f.read()
    asn1, ciphertext = decoder.decode(contents)
    f.close()

    # asking for a password
    password = input("[?] Enter password: ").encode()

    # derieving keys
    kdfinfo = asn1[0]
    cipherinfo = asn1[1]
    hmacinfo = asn1[2]
    salt = bytes(kdfinfo[0])
    iter = int(kdfinfo[1])
    key_len = int(kdfinfo[2])
    iv = bytes(cipherinfo[1])
    mac_stored = bytes(hmacinfo[1])
    keymat = pbkdf2_hmac('sha1', password, salt, iter, key_len)
    key_aes = keymat[:16]
    key_hmac = keymat[16:48]

    # reading ciphertext
    ciphertext = bytes(ciphertext)

    # before decryption checking MAC (iv+ciphertext)
    mac = hmac.new(key_hmac, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, mac_stored):
        print("[-] HMAC verification failure: wrong password or modified ciphertext!")
        return

    # decrypting ciphertext
    cipher = AES.new(key_aes, AES.MODE_ECB)
    iv_current = iv
    out = []
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = strxor(cipher.decrypt(block), iv_current)
        out.append(dec)
        iv_current = block
    plaintext = b''.join(out)

    # removing padding and writing plaintext to file
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    f = open(pfile, 'wb')
    f.write(plaintext)
    f.close()
def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()

