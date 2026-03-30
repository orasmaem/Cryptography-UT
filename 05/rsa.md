Key generation in RSA:
```text
1. Choose two distinct prime numbers p and q (usually 1024 bits)
2. Compute N = p · q (2048 bits)
3. Compute φ(N) = (p − 1)(q − 1)
4. Choose an integer e such that e and φ(N) are coprime
5. Find an integer d such that d · e ≡ 1 (mod φ(N))
N - modulus
e - public exponent (encryption exponent)
d - private exponent (decryption exponent)
Public key: (N, e)
Private key: (d)
```

In this homework I implemented an RSA encryption and signing tool, with four modes in which it can be run:

1. Encrypt
  * To encrypt, we take the message m to the power of e(public exponent) and perform mᵉ mod N
  * this will produce c (ciphertext)
2. Decrypt
  * To decrypt, we take ciphertext c to the power of d(private exponent) and perform cᵈ mod N
  * this will give us back the message m
3. Sign
  * In signing we reverse the keys
  * Encryption with the private key, decryption with the public key
4. Verify
  * Verifies the signature
It supports private and public keys in PEM and DER formats

Encryption and signing done according to the PKCS#1 v1.5 standard

Private key DER encoded structure:
```text
0 1209: SEQUENCE {
   4    1:   INTEGER 0
   7   13:   SEQUENCE {
   9    9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
  20    0:     NULL
         :     }
  22 1187:   OCTET STRING, encapsulates {
  26 1183:     SEQUENCE {
  30    1:       INTEGER 0
  33  256:       INTEGER <-modulus
         :         01 98 25 B8 67 D4 FA 1C 9C 80 64 72 ED 52 1F 2A
         :         E0 F1 33 5D 14 D3 4A 00 D7 0D 10 22 F2 7A 9A 49
         :         C9 72 D6 82 93 36 BE 95 8A E4 50 5C D3 8D BE 30
         :         BF 3A 67 D0 95 00 E8 11 33 DF 28 07 92 B7 23 2A
         :         AA 0F C2 E6 14 1C AB 7E 0A 05 C8 78 41 4D 67 78
         :         CC 14 C0 49 D2 B0 04 C5 84 08 18 57 BA C5 52 E8
         :         04 2F 27 AA D4 EE B9 25 7D BF 4E A2 2D 9C 48 AB
         :         14 BC 15 60 93 97 77 82 4D 3D 84 E6 D7 ED 9A A0
         :                 [ Another 128 bytes skipped ]
 293    3:       INTEGER 65537 <- public exponent
 298  256:       INTEGER <- private exponent d
         :         01 85 13 F8 4D EB 26 9E DD C6 3B 7B 9F A6 D8 95
         :         5C A8 32 A9 BA 2F 8D 6D 6D 94 43 5C BD 40 89 12
         :         6C 1A B0 48 FB A3 85 5D 33 71 60 F6 8C A9 A3 B3
         :         FE A7 E3 CD 60 2D E4 0C 7A 21 72 9C 7D 8D 5D D5
         :         CF 16 85 5A 25 B4 0A FB 74 FC 7C 55 BF 12 D5 DF
         :         BE D4 CD 55 D2 A5 FF 76 76 DD EC AE BD 1A 5C 65
         :         57 8F C8 45 BF 04 EF B4 C0 C1 FD 68 F7 07 F3 F2
         :         3B 2A ED 4A 0A 88 AA E1 A9 56 4A FA 70 BF 4D D6
         :                 [ Another 128 bytes skipped ]
 558  128:       INTEGER <- prime p
         :         1B 8A 8F 21 AE F5 F8 1C 1D 8A C4 3D 0A 1C 55 5D
         :         9B 65 20 A5 3F DE 76 61 F6 98 58 AD 55 26 14 DE
         :         05 22 84 23 49 34 02 F7 3E D2 EF DB 8F 82 8B 8D
         :         BD 5A 50 5A C5 BC 57 E1 F5 AF DF 36 14 A8 6D 37
         :         84 24 1F 13 F9 54 9C FD 71 3E 15 2B 79 B8 62 77
         :         84 67 C7 45 FB 3B C8 2C BB B7 66 90 BA 50 4D 08
         :         7E E0 B3 9A 18 8E 87 21 4B 24 94 58 42 0B E3 4C
         :         A6 AB E3 9F 11 1A D6 90 BB F3 B4 6C 94 E1 A3 03
 689  128:       INTEGER <- prime q
         :         0E D1 CA 60 77 94 F5 77 10 0E 57 87 35 D7 87 13
         :         C3 AE C8 5F 86 59 D4 A7 EC 40 35 DF 91 C5 B0 3D
         :         E4 6A 9B A7 35 20 E7 0D 34 51 36 B3 51 73 A1 B7
         :         0A 0C EA 2A 34 BC 8C 2A 72 DB 98 0D 35 C9 D0 29
         :         7D F7 F9 56 01 04 B7 56 FB 7C 5E CB 67 4E 59 1A
         :         0A 93 6B 4B 67 DC 28 46 BC F4 A3 9D BE 82 A5 F4
         :         24 6D 7D DD 0F B8 06 A2 3F D1 6E 46 2F F2 BB B6
         :         C8 B9 7B FA 94 E4 30 23 60 F3 31 B2 98 4D E1 53
 820  128:       INTEGER <- exponent1 = d mod (p - 1)
         :         09 0D A0 05 3B 85 21 5C E4 9D 23 EA C8 B3 0D A0
         :         AA 9F 30 7F 01 A2 B8 19 75 BD 18 91 49 C7 2D DE
         :         D9 A3 41 FA 73 6A C4 7A CF CC F9 09 9C 80 16 2D
         :         AE 8B CC 94 3A 21 B2 65 D5 A4 4D 64 72 9F F6 DE
         :         E3 F2 17 C1 32 19 8D 4D 86 77 18 F0 64 9F A6 C6
         :         90 E0 A8 51 A9 C7 3A 02 F2 65 D4 32 48 FC 72 86
         :         13 66 FB C2 F0 C5 91 47 F1 72 81 CD 0D 50 E9 13
         :         DE 49 EC 95 F2 42 77 3B B6 7C E2 D7 3A 8D 7D 4F
 951  128:       INTEGER <- exponent2 = d mod (q - 1)
         :         06 D1 E5 20 9F E7 9D 4F 3D C4 5B E3 8D 93 B2 46
         :         16 37 C9 5E AC A5 8A 87 FC E1 4F E9 A3 5C 26 CF
         :         54 DE FA E2 E8 40 4C 14 77 8F 28 6D 3D 7E C9 5D
         :         42 F2 CE 90 BD D4 47 6D 01 8E AD 5A E6 F6 09 26
         :         0F 22 9F 4C 45 0B B6 94 01 08 2B 57 D0 22 EE 3E
         :         5D BF 9A 11 09 AA F7 9E 16 37 3F 54 C8 E7 B7 17
         :         B3 EB EF 90 5C 3B 84 52 06 AC 8A E3 22 0D C2 F5
         :         4B 4A 91 13 B0 91 92 D5 B5 38 36 16 CA A0 8C A1
1082  128:       INTEGER <- coefficient = q^(-1) mod p
         :         0D 85 08 12 B4 B1 2B EB 9F E4 3C 54 89 63 F4 79
         :         54 EA 9B 9E 14 D5 05 84 24 9C 62 EC 93 79 8B F8
         :         1D 3F D4 59 4F BD 96 D9 EE 0E DF A0 D4 0B 59 80
         :         13 F1 EE 76 F0 07 18 9A 1F 57 86 2A 89 1C E7 D9
         :         6E 51 09 F2 6A C3 F3 04 02 59 32 B8 17 7C 3E 0B
         :         D5 95 A7 96 48 9A 49 80 67 6B 4B F3 A6 4F DD C6
         :         FC B5 36 44 F4 37 CE F4 59 85 39 3C 23 5F 7B 5F
         :         F5 E6 96 0C 89 F4 3A F1 86 87 1D 8D DC 00 95 D1
         :       }
         :     }
         :   }
```

Public key structure:
```text
0 289: SEQUENCE {
  4  13:   SEQUENCE { <- public key algorithm to which this public key corresponds
  6   9:     OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
 17   0:     NULL
       :     }
 19 270:   BIT STRING, encapsulates {
 24 265:     SEQUENCE {
 28 256:       INTEGER <- RSA modulus
       :         01 98 25 B8 67 D4 FA 1C 9C 80 64 72 ED 52 1F 2A
       :         E0 F1 33 5D 14 D3 4A 00 D7 0D 10 22 F2 7A 9A 49
       :         C9 72 D6 82 93 36 BE 95 8A E4 50 5C D3 8D BE 30
       :         BF 3A 67 D0 95 00 E8 11 33 DF 28 07 92 B7 23 2A
       :         AA 0F C2 E6 14 1C AB 7E 0A 05 C8 78 41 4D 67 78
       :         CC 14 C0 49 D2 B0 04 C5 84 08 18 57 BA C5 52 E8
       :         04 2F 27 AA D4 EE B9 25 7D BF 4E A2 2D 9C 48 AB
       :         14 BC 15 60 93 97 77 82 4D 3D 84 E6 D7 ED 9A A0
       :                 [ Another 128 bytes skipped ]
288   3:       INTEGER 65537 <- public exponent
       :       }
       :     }
       :   }
```
