#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from secp256r1 import curve
from pyasn1.codec.der import decoder

def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bi(b):
    # converts bytes to integer
    i = 0
    for char in b:
        i <<= 8
        i |= char
    return i

# --------------- asn1 DER encoder
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

# --------------- asn1 DER encoder end


def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads EC private key file and returns the private key integer (d)
    content = open(filename, 'rb').read()
    der = pem_to_der(content)
    keyinfo = decoder.decode(der)[0]
    ec_private_key = decoder.decode(keyinfo[2].asOctets())[0]
    d = bi(ec_private_key[1].asOctets())

    return d

def get_pubkey(filename):
    # reads EC public key file and returns coordinates (x, y) of the public key point
    # didn't take point compression into consideration here
    content = open(filename, 'rb').read()
    der = pem_to_der(content)
    keyinfo = decoder.decode(der)[0]
    point = keyinfo[1].asOctets()
    x = bi(point[1:33])
    y = bi(point[33:65])

    return (x,y)

def ecdsa_sign(keyfile, filetosign, signaturefile):

    # get the private key
    d = get_privkey(keyfile)

    # calculate SHA-384 hash of the file to be signed
    digest = hashlib.sha384(open(filetosign, 'rb').read()).digest()

    # truncate the hash value to the curve size
    digest = digest[:(curve.n.bit_length() + 7) // 8]

    # convert hash to integer
    h = bi(digest)

    # generate a random nonce k in the range [1, n-1]
    while True:
        k = bi(os.urandom((curve.n.bit_length() + 7) // 8))
        if 1 <= k < curve.n:
            break

    # calculate ECDSA signature components r and s
    while True:
        r = curve.mul(curve.g, k)[0] % curve.n
        s = (pow(k, -1, curve.n) * (h + r * d)) % curve.n
        if s != 0:
            break
        #Restart if s = 0
        while True:
            k = bi(os.urandom((curve.n.bit_length() + 7) // 8))
            if 1 <= k < curve.n:
                break

    # DER-encode r and s
    structure = asn1_sequence(asn1_integer(r) + asn1_integer(s))

    # write DER structure to file
    open(signaturefile, 'wb').write(structure)

def ecdsa_verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    # get the public key point Q
    Q = get_pubkey(keyfile)

    # read signature values r and s
    signature = decoder.decode(open(signaturefile, 'rb').read())[0]
    r = int(signature[0])
    s = int(signature[1])

    # calculate SHA-384 hash of the file
    digest = hashlib.sha384(open(filetoverify, 'rb').read()).digest()

    # truncate the hash value to the curve size
    digest = digest[:(curve.n.bit_length() + 7) // 8]

    # convert hash to integer
    h = bi(digest)

    # calculate R' 
    s_inverse = pow(s, -1, curve.n)
    g_multiplier = (h * s_inverse) % curve.n
    q_multiplier = (r * s_inverse) % curve.n
    R = curve.add(curve.mul(curve.g, g_multiplier), curve.mul(list(Q), q_multiplier))

    # Verification successful if R′.x = r mod n
    R[0] = R[0] % curve.n
    if R[0] == r:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'sign':
    ecdsa_sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    ecdsa_verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
