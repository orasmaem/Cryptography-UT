In this homework I implemented a tool that has two modes:
1. MAC mode:
  * Specify the file, for which we want to calculate the message authentication code
  * The tool will ask for a key
  * The tool prints out the MAC value calculated using HMAC-SHA256 and the entered key and also stores the value in a file with .hmac extension
  * Supports HMAC-SHA256 algorithm
   
2. Verify mode:
   * It takes the file, whose MAC should be verified
   * Reads the value from the file with .hmac extension and prints it
   * Asks for the key
   * Calculates the MAC value of the file using the key
   * If the calculated MAC matches the MAC from the file, a success message is shown.
   * Supports HMAC-MD5, HMAC-SHA1 and HMAC-SHA256 algorithms
  
The MAC value in the .hmac file is stored in an ASN1 structure called DigestInfo:

```text
SEQUENCE {
  SEQUENCE {
    OBJECT IDENTIFIER: sha-256 (2.16.840.1.101.3.4.2.1)
    NULL
  }
  OCTET STRING:
    1D 88 80 3F 25 98 0A CA 59 7F A6 AA F8 5D BC DA
    D0 E0 FC D7 63 E2 39 74 88 42 30 FA 23 87 A9 47
}
```
