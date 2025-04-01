# FProt

**FProt** is a command-line utility for securely encrypting and decrypting data using the **AES-256-GCM** algorithm.

The software operates as a stream processor, reading from **stdin** and writing to **stdout**, making it easy to integrate into pipelines and scripts. 

> [!WARNING] 
> The encryption key (256-bit) is derived from a user-provided password using the **Argon2id** key derivation function, which offers strong resistance against brute-force attacks. However, security is only as strong as the password chosen—weak passwords may compromise protection.  

> [!NOTE]
> Although the standard nonce size in AES GCM is 12 bytes, in this implementation it was chosen to use a 16 byte nonce. This choice is allowed by NIST [(NIST Special Publication 800-38D, Section. 8.2.2)](https://csrc.nist.gov/pubs/sp/800/38/d/final) and recommended in case of randomly generated nonces.
## 🚀 Usage
```sh
# Encrypting a file
fprot encrypt -p mypassword < plain.txt > cipher.fprot

# Decrypting a file
fprot decrypt -p mypassword < cipher.fprot > plain.txt
```

## 🔧 Building
```sh
# 1) Clone the repository 
git clone https://github.com/FrancescoValentini/FProt && cd FProt

# 2) Build
go build .
```

## 📜 Encrypted File Structure
```text
|--------------------------------|
|     ARGON2id SALT (16 Byte)    |
|   (only if used with -p flag)  |
|--------------------------------|
|         NONCE (16 Byte)        |
|--------------------------------|
|     CHUNK COUNTER (4 Byte)     |
|--------------------------------|
|                                |
|                                |
|    ENCRYPTED CHUNK (128 KB)    |
|                                |
|                                |
|--------------------------------|
|  AUTHENTICATION TAG (16 Byte)  |
|--------------------------------|
```
### 🛠 Hexdump example
To inspect an encrypted message, you can use `xxd`:
```bash
echo -n "test" | fprot encrypt -p password | xxd
```
**Output:**
```text
00000000: 2ec5 b652 9ff7 1ab0 5f9d e083 ceea 1639  ...R...._......9
00000010: 7f45 2154 a676 65c5 644d 08a5 937f d4ab  .E!T.ve.dM......
00000020: 0000 0000 16ec 8c39 ac6c 7276 b4b5 ced3  .......9.lrv....
00000030: ea92 9456 42f8 2419                      ...VB.$.
```
```text
|----------------------------------|
| 2ec5b6529ff71ab05f9de083ceea1639 | # ARGON2id Salt
|----------------------------------|
| 7f452154a67665c5644d08a5937fd4ab | # AES-GCM Nonce 
|----------------------------------|
|             00000000             | # Chunk counter
|----------------------------------|
|                                  |
|             16ec8c39             | # Encrypted chunk
|                                  |
|----------------------------------|
| ac6c7276b4b5ced3ea92945642f82419 | # Authentication tag
|----------------------------------|
```
