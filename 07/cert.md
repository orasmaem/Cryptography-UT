In this homework I played the role of a certificate authority, who gets a certificate signing request and has to issue a certificate. 


Below is the DER encoded structure of the certificate:

```text
0 1060: SEQUENCE { <- consists of three fields 1)tbsCertificate, 2)signatureAlgorithm, 3)signatureValue
   4  524:   SEQUENCE { <- tbs (to be signed)
   8    3:     [0] { <- version number 
  10    1:       INTEGER 2
         :       }
  13    2:     INTEGER 777 <- serial number, must be unique for each certificate
  17   13:     SEQUENCE { <- same algorithm value as in the outer sequence
  19    9:       OBJECT IDENTIFIER
         :         sha256WithRSAEncryption (1 2 840 113549 1 1 11)
  30    0:       NULL
         :       }
  32   86:     SEQUENCE { <- issuer's identity
  34   11:       SET {
  36    9:         SEQUENCE {
  38    3:           OBJECT IDENTIFIER countryName (2 5 4 6)
  43    2:           PrintableString 'US'
         :           }
         :         }
  47   24:       SET {
  49   22:         SEQUENCE {
  51    3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
  56   15:           PrintableString 'Trustworthy Inc'
         :           }
         :         }
  73   15:       SET {
  75   13:         SEQUENCE {
  77    3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
  82    6:           PrintableString 'IT dep'
         :           }
         :         }
  90   28:       SET {
  92   26:         SEQUENCE {
  94    3:           OBJECT IDENTIFIER commonName (2 5 4 3)
  99   19:           PrintableString 'Trustworthy Root CA'
         :           }
         :         }
         :       }
 120   30:     SEQUENCE { <- validity period
 122   13:       UTCTime 01/01/2020 01:01:01 GMT
 137   13:       UTCTime 01/01/2030 01:01:01 GMT
         :       }
 152   22:     SEQUENCE { <- subject
 154   20:       SET {
 156   18:         SEQUENCE {
 158    3:           OBJECT IDENTIFIER commonName (2 5 4 3)
 163   11:           UTF8String 'example.com'
         :           }
         :         }
         :       }
 176  290:     SEQUENCE { <- subjectPublicKeyInfo
 180   13:       SEQUENCE {
 182    9:         OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 193    0:         NULL
         :         }
 195  271:       BIT STRING, encapsulates {
 200  266:         SEQUENCE {
 204  257:           INTEGER
         :             00 8D 7F 97 AE 81 A6 FD B5 60 91 4C 79 56 E8 1B
         :             68 FA 76 24 56 0E FA CC E6 0C 66 98 78 72 85 60
         :             2F 46 CC FA C6 42 24 EE 84 1C B9 26 36 D7 A9 D3
         :             B1 4B 67 FE 8D 55 73 ED 87 D3 92 30 4E 6F 87 3E
         :             39 9B 3D B0 74 FB B4 58 4F 65 5D 56 3C 35 1F DC
         :             53 0F 11 6D 9A 36 07 51 4B 71 BC 1E 76 FE 5E 28
         :             A3 34 48 2C 72 A7 F3 46 2E 1A 87 AD 21 59 60 D1
         :             80 A3 96 E8 64 FE D6 05 7A 74 27 E7 CC 30 FE 5E
         :                     [ Another 129 bytes skipped ]
 465    3:           INTEGER 65537
         :           }
         :         }
         :       }
 470   60:     [3] {
 472   58:       SEQUENCE { <- extensions
 474   15:         SEQUENCE {
 476    3:           OBJECT IDENTIFIER basicConstraints (2 5 29 19)
 481    1:           BOOLEAN TRUE
 484    5:           OCTET STRING, encapsulates {
 486    3:             SEQUENCE {
 488    1:               BOOLEAN FALSE
         :               }
         :             }
         :           }
 491   15:         SEQUENCE {
 493    3:           OBJECT IDENTIFIER keyUsage (2 5 29 15)
 498    1:           BOOLEAN TRUE
 501    5:           OCTET STRING, encapsulates {
 503    3:             BIT STRING 7 unused bits
         :               '000000001'B (bit 0)
         :               Error: Spurious zero bits in bitstring.
         :             }
         :           }
 508   22:         SEQUENCE {
 510    3:           OBJECT IDENTIFIER extKeyUsage (2 5 29 37)
 515    1:           BOOLEAN TRUE
 518   12:           OCTET STRING, encapsulates {
 520   10:             SEQUENCE {
 522    8:               OBJECT IDENTIFIER serverAuth (1 3 6 1 5 5 7 3 1)
         :               }
         :             }
         :           }
         :         }
         :       }
         :     }
 532   13:   SEQUENCE { <- signature algorithm that was used to sign the tbsSignature field
 534    9:     OBJECT IDENTIFIER sha256WithRSAEncryption (1 2 840 113549 1 1 11)
 545    0:     NULL
         :     }
 547  513:   BIT STRING <- signature value encoded as a bitstring
         :     21 DE E5 17 AA 1A 0C 1C F2 D1 0D 07 72 7C 67 87
         :     3D 12 33 07 30 FE 01 37 92 31 E0 ED D5 07 04 AC
         :     C0 40 93 1B 5F 5D 58 0A 63 D7 2A 44 79 8D 92 C4
         :     03 CE 01 15 6D E8 FE 96 C7 CE 67 96 89 67 10 FB
         :     47 08 DF 09 BE EE 22 16 F9 15 5E F0 1D AB 54 01
         :     3A 8C 49 AA 66 05 9E B2 F8 E7 0A 73 B6 79 97 23
         :     7A E4 35 4E 2D 45 7B 6A D5 75 18 7F 5C 6A 7B DF
         :     5E B8 1D 12 59 25 AC A2 E9 B6 17 F0 01 4E 04 3A
         :             [ Another 384 bytes skipped ]
         :   }
```

Distinguished Name (DN) in X.509 Certificate. 
* It is a notation for identifying an entity, and it can contain the following fields:
* CN = Common Name
* O = Organization
* OU = Organizational Unit
* C = Country
* L = Locality
* ST = State or Province



Certificate extensions allow us to specify more details about the certificate and its holder. Below is the structure of a certificate extension:





```text
Extension  ::=  SEQUENCE  {
     extnId        OBJECT IDENTIFIER,
     critical      BOOLEAN DEFAULT FALSE,
     extnValue     OCTET STRING
}
```
the critical field is used to specify how should software that does not reqognize the extension, handle the extension. If critical is set to true, and the software does not reqognize the extension, the certificate is rejected.

Below is the structure of a CSR:

```text
Certificate Request:
    Data: <- by signing all of this data, we prove to the CA, that we have access to the corresponding private key
        Version: 1 (0x0)
        Subject: C = EE, ST = Tartumaa, L = Tartu, O = UT, CN = example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus: <- the public key
                    00:8d:7f:97:ae:81:a6:fd:b5:60:91:4c:79:56:e8:
                    1b:68:fa:76:24:56:0e:fa:cc:e6:0c:66:98:78:72:
                    85:60:2f:46:cc:fa:c6:42:24:ee:84:1c:b9:26:36:
                    d7:a9:d3:b1:4b:67:fe:8d:55:73:ed:87:d3:92:30:
                    4e:6f:87:3e:39:9b:3d:b0:74:fb:b4:58:4f:65:5d:
                    56:3c:35:1f:dc:53:0f:11:6d:9a:36:07:51:4b:71:
                    bc:1e:76:fe:5e:28:a3:34:48:2c:72:a7:f3:46:2e:
                    1a:87:ad:21:59:60:d1:80:a3:96:e8:64:fe:d6:05:
                    7a:74:27:e7:cc:30:fe:5e:32:10:11:ed:00:d9:a7:
                    9b:6f:de:d0:18:ba:b1:a7:1b:90:eb:9a:ef:17:23:
                    16:7e:d6:e7:9e:0b:76:f4:10:24:06:1b:05:1e:0f:
                    5a:20:26:a0:c5:c7:1a:92:35:da:72:9a:e2:e9:4a:
                    0a:da:91:40:89:9a:b5:61:07:94:f4:fd:04:20:7d:
                    0f:38:fa:9a:43:6c:30:11:32:66:f3:ad:06:d9:27:
                    1a:3a:92:7b:00:fd:2b:5f:ad:95:83:1b:e2:58:b1:
                    07:1a:04:14:71:1d:4c:95:c2:ea:e0:f3:0a:c7:9d:
                    ac:83:a3:b2:b8:dd:a2:da:04:52:39:9b:f6:ba:93:
                    26:bf
                Exponent: 65537 (0x10001)
        Attributes:
            challengePassword        :test
            Requested Extensions:
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value: <- all of this data is signed using the private key of the entity who made the CSR
        85:23:55:1f:03:41:61:3a:1c:df:3f:a3:58:13:aa:a6:9f:e3:
        51:4e:26:19:43:f5:9b:b2:ba:75:cd:ee:98:bf:c3:c9:a3:58:
        3b:23:cc:84:b1:1e:ae:dc:ad:76:49:ed:5a:38:a8:6b:9b:d3:
        3e:3c:57:67:6f:8b:5a:2c:bb:96:fa:72:6c:51:99:eb:0f:5b:
        e9:6e:b9:92:58:a5:05:26:9e:c1:f3:e7:a0:e3:b1:71:f0:fc:
        7b:e4:0e:27:c8:66:57:60:dc:17:84:b3:f1:0a:0b:63:fd:1e:
        1a:89:b9:6c:42:bf:5d:6b:b0:35:cd:91:a6:6a:b3:08:70:c1:
        14:64:a2:be:4a:b1:9d:84:50:4b:b0:bb:8d:a6:4c:15:d8:a2:
        18:cb:c0:1d:8e:f0:6c:a0:ce:15:76:73:36:96:73:d3:d4:5b:
        f5:42:81:82:37:0d:bb:1f:0c:99:43:8a:c8:ba:48:ed:f4:c5:
        48:39:c5:19:22:d1:f0:0d:6b:69:48:0a:a4:c1:95:47:02:40:
        b7:de:f7:94:fb:e7:c6:c9:2b:2a:af:b7:ad:e9:75:87:66:be:
        02:16:35:52:4e:cc:30:60:f3:64:a6:c3:6f:c9:75:66:8f:c9:
        9b:23:3a:a4:d4:c2:90:7d:85:68:82:e8:b3:57:4c:0e:c5:fb:
        85:0c:6b:c3
-----BEGIN CERTIFICATE REQUEST-----
MIICrTCCAZUCAQAwUzELMAkGA1UEBhMCRUUxETAPBgNVBAgMCFRhcnR1bWFhMQ4w
DAYDVQQHDAVUYXJ0dTELMAkGA1UECgwCVVQxFDASBgNVBAMMC2V4YW1wbGUuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjX+XroGm/bVgkUx5Vugb
aPp2JFYO+szmDGaYeHKFYC9GzPrGQiTuhBy5JjbXqdOxS2f+jVVz7YfTkjBOb4c+
OZs9sHT7tFhPZV1WPDUf3FMPEW2aNgdRS3G8Hnb+XiijNEgscqfzRi4ah60hWWDR
gKOW6GT+1gV6dCfnzDD+XjIQEe0A2aebb97QGLqxpxuQ65rvFyMWftbnngt29BAk
BhsFHg9aICagxccakjXacpri6UoK2pFAiZq1YQeU9P0EIH0POPqaQ2wwETJm860G
2ScaOpJ7AP0rX62VgxviWLEHGgQUcR1MlcLq4PMKx52sg6OyuN2i2gRSOZv2upMm
vwIDAQABoBUwEwYJKoZIhvcNAQkHMQYMBHRlc3QwDQYJKoZIhvcNAQELBQADggEB
AIUjVR8DQWE6HN8/o1gTqqaf41FOJhlD9ZuyunXN7pi/w8mjWDsjzISxHq7crXZJ
7Vo4qGub0z48V2dvi1osu5b6cmxRmesPW+luuZJYpQUmnsHz56DjsXHw/HvkDifI
Zldg3BeEs/EKC2P9HhqJuWxCv11rsDXNkaZqswhwwRRkor5KsZ2EUEuwu42mTBXY
ohjLwB2O8GygzhV2czaWc9PUW/VCgYI3DbsfDJlDisi6SO30xUg5xRki0fANa2lI
CqTBlUcCQLfe95T758bJKyqvt63pdYdmvgIWNVJOzDBg82Smw2/JdWaPyZsjOqTU
wpB9hWiC6LNXTA7F+4UMa8M=
-----END CERTIFICATE REQUEST-----
```

