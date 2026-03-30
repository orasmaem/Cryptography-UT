#!/usr/bin/env python3

import argparse, codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took 15 hours


# parse arguments
parser = argparse.ArgumentParser(description='issue TLS server certificate based on CSR', add_help=False)
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("CA_private_key_file", help="CA private key (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()

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
        if value[0] & 0x80:
            value = b"\x00" + value

    return bytes([0x02]) + asn1_len(value) + value

def asn1_bitstring(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    bits = len(bitstr)
    if bits == 0:
        value = b"\x00"
        return bytes([0x03]) + asn1_len(value) + value

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
        if node == 0:
            valuebytes.append(0)
            continue

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
def asn1_bitstring_der(octets):
    value = b"\x00" + octets
    return bytes([0x03]) + asn1_len(value) + value

#==== ASN1 encoder end ====

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----END CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = content.replace(b"-----BEGIN RSA PRIVATE KEY-----", b"")
        content = content.replace(b"-----END RSA PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

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

def digestinfo_der(m):
    # returns ASN.1 DER-encoded DigestInfo structure containing SHA256 digest of m
    digest = hashlib.sha256(m).digest()
    alg = asn1_sequence(
        asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]) +
        asn1_null()
    )
    der = asn1_sequence(alg + asn1_octetstring(digest))
    return der


def sign(m, keyfile):
    # signs DigestInfo of message m
    n, d = get_privkey(keyfile)
    di = digestinfo_der(m)
    padded = pkcsv15pad_sign(di, n)
    k = (n.bit_length() + 7) // 8
    s = pow(bi(padded), d, n)
    signature = ib(s, k)
    return signature


def get_subject_cn(csr_der):
    # returns CommonName value from CSR's Distinguished Name field
    csr = decoder.decode(csr_der)[0]
    dn = csr[0][1]
    oid = [2, 5, 4, 3]
    # looping over Distinguished Name entries until CN found
    for entry in dn:
        for attribute_type_and_value in entry:
            if list(attribute_type_and_value[0]) == oid:
                return str(attribute_type_and_value[1])

def get_subjectPublicKeyInfo(csr_der):
    # returns DER-encoded subjectPublicKeyInfo from CSR
    return encoder.encode(decoder.decode(csr_der)[0][0][2])

def get_subjectName(cert_der):
    # returns DER-encoded subject name from CA certificate
    return encoder.encode(decoder.decode(cert_der)[0][0][5])

def issue_certificate(private_key_file, issuer, subject, pubkey):
    # receives CA private key filename, DER-encoded CA Distinguished Name, self-constructed DER-encoded subject's Distinguished Name and DER-encoded subjectPublicKeyInfo
    # returns X.509v3 certificate in PEM format

    signature_algorithm = asn1_sequence(
        asn1_objectidentifier([1, 2, 840, 113549, 1, 1, 11]) +
        asn1_null()
    )

    validity = asn1_sequence(
        asn1_utctime(b"200101010101Z") +
        asn1_utctime(b"300101010101Z")
    )

    extensions = asn1_sequence(
        # basic constraints
        asn1_sequence(
            asn1_objectidentifier([2, 5, 29, 19]) +
            asn1_boolean(True) +
            asn1_octetstring(asn1_sequence(asn1_boolean(False)))
        ) +
        # key usage
        asn1_sequence(
            asn1_objectidentifier([2, 5, 29, 15]) +
            asn1_boolean(True) +
            asn1_octetstring(asn1_bitstring("100000000"))
        ) +
        # extended key usage
        asn1_sequence(
            asn1_objectidentifier([2, 5, 29, 37]) +
            asn1_boolean(True) +
            asn1_octetstring(
                asn1_sequence(
                    asn1_objectidentifier([1, 3, 6, 1, 5, 5, 7, 3, 1])
                )
            )
        )
    )


    to_be_signed = asn1_sequence(
        #version
        asn1_tag_explicit(asn1_integer(2), 0) +
        #serial number
        asn1_integer(777) +
        signature_algorithm +
        issuer +
        validity +
        subject +
        pubkey +
        extensions
    )

    signature = sign(to_be_signed, private_key_file)

    cert_der = asn1_sequence(
        to_be_signed +
        signature_algorithm +
        asn1_bitstring_der(signature)
    )

    cert_b64 = codecs.encode(cert_der, 'base64').replace(b'\n', b'')
    pem = ""
    for i in range(0, len(cert_b64), 64):
        pem += cert_b64[i:i+64] + b"\n"

    return pem

# obtain subject's CN from CSR
csr_der = pem_to_der(open(args.csr_file, 'rb').read())
subject_cn_text = get_subject_cn(csr_der)

print("[+] Issuing certificate for \"%s\"" % (subject_cn_text))

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)

# construct subject name DN for end-entity's certificate
subject = asn1_sequence(
    asn1_set(
        asn1_sequence(
            asn1_objectidentifier([2, 5, 4, 3]) +
            asn1_utf8string(subject_cn_text.encode())
        )
    )
)

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, 'rb').read())
CAsubject = get_subjectName(CAcert)

# issue certificate
cert_pem = issue_certificate(args.CA_private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, 'wb').write(cert_pem)