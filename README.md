# qlock
> (pronounced 'clock')

a CLI tool in rust for encrypting data locally with XChaCha20Poly1305.

keys are also encrypted using a separate nonce, and argon2 is used for hashing.

### getting started/install

cargo build --release && cp target/release/qlock /usr/local/bin/qlock

### usage

```bash
# encrypt a file
qlock -e <file path>

# decrypt the encrypted file
qlock -d <path to .qlock file>

# list out the saved hashes and associated input & output files
qlock ls

# specify an optional output to name the encrypted file, note that `.qlock` will be appended to it automatically.
qlock -e <path to file you want to encrypt> -o <output file name>

# specify an optional output to name the decrypted file, including the file extension to use.
# by default, it will use the original file name saved from when the file was encrypted.
qlock -d <path to .qlock file> -o <output file name>
```
