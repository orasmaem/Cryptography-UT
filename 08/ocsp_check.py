#!/usr/bin/env python3

import codecs, datetime, hashlib, re, sys, socket # do not use any other imports/libraries
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280

# took 9 hours

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






#==== ASN1 encoder end ====


def pem_to_der(content):
    # converts PEM-encoded X.509 certificate (if it is in PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    return encoder.encode(decoder.decode(cert)[0][0][5])

def get_key(cert):
    return decoder.decode(cert)[0][0][6][1].asOctets()

def get_serial(cert):
    return int(decoder.decode(cert)[0][0][1])

def produce_request(cert, issuer_cert):
    # makes OCSP request in ASN.1 DER form

    # construct CertID (use SHA1)
    issuer_name = get_name(issuer_cert)
    issuer_key = get_key(issuer_cert)
    serial = get_serial(cert)

    issuer_name_hash = hashlib.sha1(issuer_name).digest()
    issuer_key_hash = hashlib.sha1(issuer_key).digest()

    cert_id = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier([1, 3, 14, 3, 2, 26]) +
            asn1_null()
        ) +
        asn1_octetstring(issuer_name_hash) +
        asn1_octetstring(issuer_key_hash) +
        asn1_integer(serial)
    )

    print("[+] OCSP request for serial:", serial)

    # construct entire OCSP request
    request = asn1_sequence(
        # tbsRequest
        asn1_sequence(
            # requestList
            asn1_sequence(
                # request
                asn1_sequence(
                    cert_id
                )
            )
        )
    )

    return request

def send_req(ocsp_req, ocsp_url):
    # sends OCSP request to OCSP responder

    # parse OCSP responder's url
    url = urlparse(ocsp_url)
    host = url.hostname
    port = 80
    path = '/'

    
    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("[+] Connecting to %s..." % (host))
    s.connect((host, port))

    # send HTTP POST request
    req = b"POST " + path.encode() + b" HTTP/1.1\r\n"
    req += b"Host: " + host.encode() + b"\r\n"
    req += b"Content-Type: application/ocsp-request\r\n"
    req += b"Content-Length: " + str(len(ocsp_req)).encode() + b"\r\n"
    req += b"Connection: close\r\n\r\n"
    req += ocsp_req

    s.sendall(req)

    # read HTTP response header
    header = b""
    while b"\r\n\r\n" not in header:
        chunk = s.recv(1)
        if not chunk:
            print("Connection broke")
            exit(1)
        header += chunk

    # get HTTP response length
    content_length = int(re.search(b'content-length:\\s*(\\d+)\\s', header, re.I).group(1))

    # read HTTP response body
    ocsp_resp = b''
    while len(ocsp_resp) < content_length:
        chunk = s.recv(content_length - len(ocsp_resp))
        if not chunk:
            print("Connection broke")
            exit(1)
        ocsp_resp += chunk

    s.close()

    return ocsp_resp

def get_ocsp_url(cert):
    # gets the OCSP responder's url from the certificate's AIA extension


    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    cert_obj, _ = decoder.decode(cert, asn1Spec=rfc5280.Certificate())

    # looping over certificate extensions
    for seq in cert_obj.getComponentByName('tbsCertificate').getComponentByName('extensions'):
        if str(seq.getComponentByName('extnID'))=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq.getComponentByName('extnValue'))
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.1': # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in the certificate!")
    exit(1)

def get_issuer_cert_url(cert):
    # gets the CA's certificate URL from the certificate's AIA extension (hint: see get_ocsp_url())

    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    cert_obj, _ = decoder.decode(cert, asn1Spec=rfc5280.Certificate())

    for seq in cert_obj.getComponentByName('tbsCertificate').getComponentByName('extensions'):
        if str(seq.getComponentByName('extnID')) == '1.3.6.1.5.5.7.1.1':
            ext_value = bytes(seq.getComponentByName('extnValue'))
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0]) == '1.3.6.1.5.5.7.48.2':
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] Issuer certificate url not found in the certificate!")
    exit(1)


def download_issuer_cert(issuer_cert_url):
    # downloads issuer certificate
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # parse issuer certificate url
    url = urlparse(issuer_cert_url)
    host = url.hostname
    port = 80
    path = url.path

    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # send HTTP GET request
    req = b"GET " + path.encode() + b" HTTP/1.1\r\n"
    req += b"Host: " + host.encode() + b"\r\n"
    req += b"Connection: close\r\n\r\n"

    s.sendall(req)

    # read HTTP response header
    header = b''
    while b'\r\n\r\n' not in header:
        chunk = s.recv(1)
        if not chunk:
            print("Connection broken")
            exit(1)
        header += chunk

    # get HTTP response length
    content_length = int(re.search(b'content-length:\\s*(\\d+)\\s', header, re.S+re.I).group(1))

    # read HTTP response body
    issuer_cert = b''
    while len(issuer_cert) < content_length:
        chunk = s.recv(content_length - len(issuer_cert))
        if not chunk:
            print("Connection broke")
            exit(1)
        issuer_cert += chunk

    s.close()
    issuer_cert = pem_to_der(issuer_cert)

    return issuer_cert

def parse_ocsp_resp(ocsp_resp):
    # parses OCSP response
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    response = responseBytes.getComponentByName('response')

    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    certID = response0.getComponentByName('certID')
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(response0.getComponentByName('nextUpdate')), '%Y%m%d%H%M%SZ')

    # let's assume that the certID in the response matches the certID sent in the request

    # let's assume that the response is signed by a trusted responder

    print("[+] OCSP producedAt: %s +00:00" % producedAt)
    print("[+] OCSP thisUpdate: %s +00:00" % thisUpdate)
    print("[+] OCSP nextUpdate: %s +00:00" % nextUpdate)
    print("[+] OCSP status:", certStatus)

cert = pem_to_der(open(sys.argv[1], 'rb').read())

ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)
issuer_cert = download_issuer_cert(issuer_cert_url)

ocsp_req = produce_request(cert, issuer_cert)
ocsp_resp = send_req(ocsp_req, ocsp_url)
parse_ocsp_resp(ocsp_resp)
