# FProt

**FProt** is a command-line utility for securely encrypting and decrypting data using the **AES-256-GCM** algorithm.

The software operates as a stream processor, reading from **stdin** and writing to **stdout**, making it easy to integrate into pipelines and scripts. 

> [!WARNING] 
> The encryption key (256-bit) is derived from a user-provided password using the **Argon2id** key derivation function, which offers strong resistance against brute-force attacks. However, security is only as strong as the password chosen—weak passwords may compromise protection.  

> [!NOTE]
> Although the standard nonce size in AES GCM is 12 bytes, in this implementation it was chosen to use a 16 byte nonce. This choice is allowed by NIST [NIST Special Publication 800-38D, Section. 8.2.2](https://csrc.nist.gov/pubs/sp/800/38/d/final)

## 🚀 Usage
```sh
# Encrypting a file with a password
fprot encrypt -p mypassword < plain.txt > cipher.fprot

# Decrypting a file with a password
fprot decrypt -p mypassword < cipher.fprot > plain.txt

# Generating ECC Keys
fprot keygen --priv-out my-private.txt --pub-out recipient-key.txt

# Encrypting a file with a public key
fprot encrypt -r recipient-key.txt < plain.txt > cipher.fprot

# Decrypting a file with a private key
fprot decrypt -s my-private.txt < cipher.fprot > plain.txt
```

## 🔧 Building
```sh
# 1) Clone the repository 
git clone https://github.com/FrancescoValentini/FProt && cd FProt

# 2) Build
go build .
```

## 📜 Encrypted File Structure
The Argon2id salt is inserted only at the beginning of the file. Each chunk consists of a nonce, a 32-bit counter, the ciphertext, and an authentication tag.

```text
|--------------------------------|
|    ARGON2id SALT (16 Bytes)    |
|   (only if used with -p flag)  |
|--------------------------------|
|         NONCE (16 Bytes)       |
|--------------------------------|
|     CHUNK COUNTER (4 Bytes)    |
|--------------------------------|
|                                |
|                                |
|    ENCRYPTED CHUNK (128 KB)    |
|                                |
|                                |
|--------------------------------|
|  AUTHENTICATION TAG (16 Bytes) |
|--------------------------------|
```

### Asymmetric encryption file structure
If asymmetric encryption is used, the header is 157 bytes in size and contains 97 bytes of ECC public key + 60 bytes composed of iv (12 bytes) + encrypted aes key (32 bytes) + AES-GCM auth tag (16 bytes)
```text
|--------------------------------|
|  ASYMMETRIC ENCRYPTION HEADER  |
|          (157 Bytes)           |
|--------------------------------|
|         NONCE (16 Bytes)       |
|--------------------------------|
|     CHUNK COUNTER (4 Bytes)    |
|--------------------------------|
|                                |
|                                |
|    ENCRYPTED CHUNK (128 KB)    |
|                                |
|                                |
|--------------------------------|
|  AUTHENTICATION TAG (16 Bytes) |
|--------------------------------|
```

### The counter
The counter is authenticated using Additional Authenticated Data (AAD) in AES-GCM and is used to prevent reorder attacks. During decryption, the software verifies that the expected counter matches the one read from the chunk. If this check fails, decryption of subsequent chunks is halted.



### 🛠 Hexdump example
To inspect an encrypted message, you can use `xxd`:
```bash
echo -n "test" | fprot encrypt -p password | xxd
```
**Output:**
```text
00000000: c951 9b2c 5f45 2e79 a888 3926 adbe 53c2  .Q.,_E.y..9&..S.
00000010: 706c a422 00c6 525f f236 d826 f4c2 b20a  pl."..R_.6.&....
00000020: 0000 0000 3173 4c42 67b0 bea3 ca0e e7aa  ....1sLBg.......
00000030: f9e3 a877 7ae6 3edd                      ...wz.>.
```
```text
|----------------------------------|
| C9519B2C5F452E79A8883926ADBE53C2 | # ARGON2id Salt
|----------------------------------|
| 706CA42200C6525FF236D826F4C2B20A | # AES-GCM Nonce 
|----------------------------------|
|             00000000             | # Chunk counter
|----------------------------------|
|                                  |
|             31734C42             | # Encrypted chunk
|                                  |
|----------------------------------|
| 67B0BEA3CA0EE7AAF9E3A8777AE63EDD | # Authentication tag
|----------------------------------|
```
## Disclaimer
I am not a professional cryptographer / developer, and this project was created primarily as my first Go project to learn the language, future updates may introduce changes without notice, potentially breaking compatibility with previous versions (e.g., changes in the encrypted file format). Use at your own risk!
