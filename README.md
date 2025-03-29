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

## 📜 Encrypted file structure
```text
|--------------------------------|
|         NONCE (16 Byte)        |
|--------------------------------|
|                                |
|                                |
|                                |
|         ENCRYPTED DATA         |
|                                |
|                                |
|                                |
|--------------------------------|
|  AUTHENTICATION TAG (16 Byte)  |
|--------------------------------|
```
### 🛠Hexdump example
To inspect an encrypted message, you can use `xxd`:
```bash
echo -n "abcdefghijklmnop" | fprot encrypt -p password -v | xxd
```
**Output:**
```text
00000000: 0af5 c993 ff78 18cd 760a 2428 44e7 9120  .....x..v.$(D..   < -- NONCE
00000010: 71ca f3d1 e0af b3f8 243e cb97 1702 6c4b  q.......$>....lK  < -- ENCRYPED DATA (abcdefghijklmnop)
00000020: a718 edde a791 7182 c33c ab39 e7e9 ef55  ......q..<.9...U  < -- AUTHENTICATION TAG
```

