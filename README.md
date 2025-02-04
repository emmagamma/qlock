# qlock
**(pronounced 'clock', because I'm annoying like that)**

a CLI tool in rust for encrypting data locally with XChaCha20Poly1305, and argon2 is used for hashing.

keys are also encrypted using a separate nonce and a user-provided password.

> this tool does not store your passwords locally. if you forget them, you wont be able to decrypt your `.qlock` files.

### Getting Started/Install

1. clone the repo and cd into it:

```bash
git clone git@github.com:emmagamma/qlock.git && cd qlock/
```

2. build the binary and copy it to your bin so you can run it:

```bash
cargo build --release && cp target/release/qlock /usr/local/bin/qlock
```

### Usage

```bash
# encrypt a file
qlock -e <file path>

# decrypt the encrypted file
qlock -d <path to .qlock file>

# list out each saved encrypted key, along with some metadata
qlock ls

# remove all the saved metadata for a given key, by name
qlock rm <key-name>

# specify an optional output to name the encrypted file, note that `.qlock` will be appended to it automatically.
# if no output name is provided, we use the original file name with `.qlock` instead of it's original extension.
qlock -e <path to file you want to encrypt> -o <output file name>

# specify an optional output to name the decrypted file, including the file extension to use.
# if no output name is provided, we use the original file name saved in `qlock_metadata.json` from when the file was encrypted.
qlock -d <path to .qlock file> -o <output file name>
```
