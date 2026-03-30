#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# took 12-14 hours (please specify here how much time your solution required)


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
    for byte in b:
        i <<= 8
        i |= byte
    return i

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


def pem_to_der(content):
    # converts PEM content to DER
    if content.lstrip().startswith(b"-----BEGIN"):
        lines = []
        for line in content.splitlines():
            if not line.startswith(b"-----"):
                lines.append(line.strip())
        return codecs.decode(b"".join(lines), "base64")
    return content

def get_pubkey(filename):
    # reads public key file encoded using SubjectPublicKeyInfo structure and returns (N, e)

    # DER-decode the DER to get RSAPublicKey DER structure, which is encoded as BITSTRING
    der = pem_to_der(open(filename, "rb").read())
    decoded = decoder.decode(der)
    spki = decoded[0]
    bitstr = spki[1]
    # convert BITSTRING to bytestring
    pub_der = bitstr.asOctets()
    # DER-decode the bytestring (which is actually DER) and return (N, e)
    decoded = decoder.decode(pub_der)
    pubkey = decoded[0]
    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file encoded using PrivateKeyInfo (PKCS#8) structure and returns (N, d)

    # DER-decode the DER to get RSAPrivateKey DER structure, which is encoded as OCTETSTRING
    der = pem_to_der(open(filename, "rb").read())
    decoded = decoder.decode(der)
    pkcs8 = decoded[0]
    octet = pkcs8[2]
    # DER-decode the octetstring (which is actually DER) and return (N, d)
    priv_der = octet.asOctets()
    decoded = decoder.decode(priv_der)
    privkey = decoded[0]
    return int(privkey[1]), int(privkey[3])


def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5

    # calculate number of bytes required to represent the modulus N
    k = (n.bit_length() + 7) // 8

    # plaintext must be at least 11 bytes smaller than the modulus
    if len(plaintext) > k - 11:
        print("Error: plaintext too long for encryption")
        sys.exit(1)
    # generate padding bytes
    ps_len = k - 3 - len(plaintext)
    ps = b""
    while len(ps) < ps_len:
        chunk = os.urandom(ps_len - len(ps))
        ps += chunk.replace(b"\x00", b"")
    padded_plaintext = b"\x00\x02" + ps + b"\x00" + plaintext
    return padded_plaintext

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5

    # calculate bytelength of modulus N
    k = (n.bit_length() + 7) // 8

    # plaintext must be at least 11 bytes smaller than the modulus N
    if len(plaintext) > k - 11:
        print("Error: plaintext too long for signing")
        sys.exit(1)
    # generate padding bytes
    ps_len = k - 3 - len(plaintext)
    padded_plaintext = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + plaintext
    return padded_plaintext

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    # validate header
    if len(plaintext) < 3:
        return plaintext

    has_valid_prefix = plaintext[0] == 0
    has_valid_block_type = plaintext[1] in (1, 2)

    if not has_valid_prefix or not has_valid_block_type:
        return plaintext
    # find end of padding
    idx = plaintext.find(b"\x00", 2)
    if idx == -1:
        return b""
    # return unpadded message
    return plaintext[idx + 1:]



def encrypt(keyfile, plaintextfile, ciphertextfile):
    n, e = get_pubkey(keyfile)
    plaintext = open(plaintextfile, "rb").read()
    padded = pkcsv15pad_encrypt(plaintext, n)
    k = (n.bit_length() + 7) // 8
    c = pow(bi(padded), e, n)
    open(ciphertextfile, "wb").write(ib(c, k))

def decrypt(keyfile, ciphertextfile, plaintextfile):
    n, d = get_privkey(keyfile)
    ciphertext = open(ciphertextfile, "rb").read()
    k = (n.bit_length() + 7) // 8
    m = pow(bi(ciphertext), d, n)
    padded = ib(m, k)
    plaintext = pkcsv15pad_remove(padded)
    open(plaintextfile, "wb").write(plaintext)

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    data = open(filename, "rb").read()
    digest = hashlib.sha256(data).digest()
    alg = asn1_sequence(
        asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]) +
        asn1_null()
    )
    der = asn1_sequence(alg + asn1_octetstring(digest))
    return der

def sign(keyfile, filetosign, signaturefile):
    n, d = get_privkey(keyfile)
    di = digestinfo_der(filetosign)
    padded = pkcsv15pad_sign(di, n)
    k = (n.bit_length() + 7) // 8
    s = pow(bi(padded), d, n)
    open(signaturefile, "wb").write(ib(s, k))

    # Warning: make sure that signaturefile produced has the same
    # length as the modulus (hint: use parametrized ib()).

def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    n, e = get_pubkey(keyfile)
    sig = open(signaturefile, "rb").read()
    k = (n.bit_length() + 7) // 8
    m = pow(bi(sig), e, n)
    padded = ib(m, k)
    expected = pkcsv15pad_sign(digestinfo_der(filetoverify), n)
    if padded == expected:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
