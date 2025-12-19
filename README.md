# FProt

**FProt** is a command-line utility for securely encrypting and decrypting data using the **AES-256-GCM** algorithm.

The software operates as a stream processor, reading from **stdin** and writing to **stdout**, making it easy to integrate into pipelines and scripts. 

> [!WARNING] 
> The encryption key (256-bit) is derived from a user-provided password using the **Argon2id** key derivation function, which offers strong resistance against brute-force attacks. However, security is only as strong as the password chosen—weak passwords may compromise protection.  

## 🚀 Usage
### 🔐 Encryption
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


### ✍🏻 Digital Signature
> [!WARNING]
> Please note that digital signatures are an experimental feature; 
> support for them in future updates is not guaranteed.
```sh
# Generating ECDSA Keys
fprot keygen --ecdsa --priv-out my-private.txt --pub-out my-public.txt

# Signing a file
fprot sign -s my-private.txt < file.txt > file_signature.bin

# Verifying a digital signature
fprot verify --sig file_signature.bin < file.txt
```

## 🔧 Building
```sh
# 1) Clone the repository 
git clone https://github.com/FrancescoValentini/FProt && cd FProt

# 2) Build
go build .
```

## 📜 Encrypted File Structure
[File format description](docs/PROTOCOL-en.md)

## Disclaimer
I am not a professional cryptographer / developer, and this project was created primarily as my first Go project to learn the language, future updates may introduce changes without notice, potentially breaking compatibility with previous versions (e.g., changes in the encrypted file format). Use at your own risk!
