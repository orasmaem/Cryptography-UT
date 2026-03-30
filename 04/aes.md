In this homework, I implemented a utility for encryption and decryption of files, using a password. It has two modes:

1. Encrypt
   * Computer calculates how many PBKDF2 iterations it can perform in one second
   * This number is used as iteration count to derive the encryption key
   * Asks for a password
   * Derives the keys
   * Encrypts the file


2. Decrypt
   * Ask for a password
   * Derive keys
   * Decrypt the ciphertext
   * Write the plaintext to a file
  
Two keys are derived from the password:
* AES-128 key for encryption/decryption
* HMAC-SHA256 key for computing and verifying the MAC over initialization vector+ciphertext

The parameters for key derivation, encryption and HMAC are asn1 encoded and stored as a header of the ciphertext file. Structure can be seen below:
  
```text
0 102: SEQUENCE {
  2  18:   SEQUENCE { <- key derivation function info
  4   8:     OCTET STRING 38 2B 6B 98 0A 46 8D 85 <- salt
 14   3:     INTEGER 1576391 <- iteration count
 19   1:     INTEGER 48 <- key length
       :     }
 22  29:   SEQUENCE { <- cipher infor
 24   9:     OBJECT IDENTIFIER aes128-CBC (2 16 840 1 101 3 4 1 2) <- encryption algorithm
 35  16:     OCTET STRING 4B 7E D3 91 41 33 48 F8 DE E5 2A FE 13 9D 9D 1E <- initialization vector
       :     }
 53  49:   SEQUENCE { <- this is the DigestInfo structure from the previous homework
 55  13:     SEQUENCE {
 57   9:       OBJECT IDENTIFIER sha-256 (2 16 840 1 101 3 4 2 1)
 68   0:       NULL
       :       }
 70  32:     OCTET STRING <- digest
       :       34 EE 83 86 C7 A0 39 AF 92 27 9B FD 34 D3 7F 19
       :       4D 4A FB 64 69 49 84 BD E6 F8 5C E4 37 7F DB B0
       :     }
       :   }
```
