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



