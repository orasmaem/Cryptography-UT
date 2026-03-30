#!/usr/bin/env python3

import codecs, hashlib, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:] # don't remove! otherwise the library import below will try to import your hmac.py
import hmac # do not use any other imports/libraries

# took about 10 hours

#==== ASN1 encoder start ====
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

def mac(filename):
    key = input("[?] Enter key: ").encode()

    hmac_object = hmac.new(key, None, hashlib.sha256)
    #print(hmac_object.copy().digest())
    #print("----------------------")
    with open(filename, "rb") as file:
        while True:
            chunk = file.read(512)
            if not chunk:
                break
            hmac_object.update(chunk)

            #print(hmac_object.copy().digest())
    digest_bytes = hmac_object.digest()
    #print(digest_bytes)


    print("[+] Calculated HMAC-SHA256:", digest_bytes.hex())

    algorithm_identifier = asn1_sequence(asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]) + asn1_null())

    #print(algorithm_identifier)

    digest_der= asn1_sequence(algorithm_identifier + asn1_octetstring(digest_bytes))

    #print(digest_der)

    print("[+] Writing HMAC DigestInfo to", filename+".hmac")

    with open(filename + ".hmac", "wb") as output:
        output.write(digest_der)

def verify(filename):
    print("[+] Reading HMAC DigestInfo from", filename+".hmac")

    der_bytes = open(filename + ".hmac", "rb").read()
    #print(der_bytes)
    #print("----------------------")
    digestInfo = decoder.decode(der_bytes)[0]
    #print(digestInfo)
    #print("----------------------")
    algo_identifyer = digestInfo[0]
    #print(algo_identifyer)
    #print("----------------------")
    algoOID = str(algo_identifyer[0])
    #print(algoOID)
    #print("----------------------")
    digest = bytes(digestInfo[1])
    #print(digest)
    #print("----------------------")

    oid_to_hash = {
        "1.2.840.113549.2.5": ("MD5", hashlib.md5),
        "1.3.14.3.2.26": ("SHA1", hashlib.sha1),
        "2.16.840.1.101.3.4.2.1": ("SHA256", hashlib.sha256),
    }
    algorithm_name, hash_constructor = oid_to_hash[algoOID]
    print(f"[+] HMAC-{algorithm_name} digest:", digest.hex())

    key_bytes = input("[?] Enter key: ").encode()

    hmac_object = hmac.new(key_bytes, None, hash_constructor)
    with open(filename, "rb") as input_file:
        while True:
            chunk_bytes = input_file.read(512)
            if not chunk_bytes:
                break
            hmac_object.update(chunk_bytes)

    digest_calculated = hmac_object.digest()
    print(f"[+] Calculated HMAC-{algorithm_name}:", digest_calculated.hex())



    if digest_calculated != digest:
        print("[-] Wrong key or message has been manipulated!")
    else:
        print("[+] HMAC verification successful!")



def usage():
    print("Usage:")
    print("-mac <filename>")
    print("-verify <filename>")
    sys.exit(1)

if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()
