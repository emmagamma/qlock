# qlock

**(pronounced 'Queue Lock', or 'clock' if ur feelin spicy?)**

A CLI tool written in Rust for encrypting files locally using XChaCha20Poly1305 and Argon2 for key-derivation.

For encrypting files locally with a password before uploading them to cloud storage or sending them over the network. A file named `qlock_metadata.json` will be created in whichever directory you run this command from. This file is sensitive and should not be shared or sent over the network. To decrypt your `.qlock` files, you need your `qlock_metadata.json` file present in the directory you run this tool from, and a password you provide for each file. Passwords are not stored locally so we suggest using a password manager.

## Installation

```bash
git clone git@github.com:emmagamma/qlock.git
cd qlock/
cargo build --release && cp target/release/qlock /usr/local/bin/qlock
```

## Usage

### Basic Commands

```bash
# Encrypt file(s)
qlock -e <file path>
qlock -e <file path> <file path> ...
qlock -e <folder>

# Decrypt file(s)
qlock -d <.qlock file path>
qlock -d <.qlock file path> <.qlock file path> ...
qlock -d <folder containing .qlock files>

# List all encrypted keys
qlock ls

# List a specific key
qlock ls <key name>

# Remove all metadata for a given key
qlock rm <key name>
```

### Multiple Files

You can encrypt/decrypt multiple files, with specific flags for each file, in one of two ways:

```bash
# Method 1: Using numbered parameters
qlock -e file1.txt file2.txt \
  -p1="password1" -p2="password2" \
  -n1="key1" -n2="key2" \
  -o1="encrypted1" -o2="encrypted2"

qlock -d file1.qlock file2.qlock \
  -p1="password1" -p2="password2" \
  -o1="decrypted1.txt" -o2="decrypted2.txt"

# Method 2: Using comma-separated lists
qlock -e file1.txt file2.txt \
  -p "password1, password2" \
  -n "key1, key2" \
  -o "encrypted1, encrypted2"

qlock -d file1.qlock file2.qlock \
  -p "password1, password2" \
  -o "decrypted1.txt, decrypted2.txt"
```

### Directory Encryption with per-file flags

```bash
# Encrypt all files in a directory with flags using numbered parameters
qlock -e path-to-folder-with-three-files/ \
  -p1="password1" -p2="password2" -p3="password3" \
  -n1="key1" -n2="key2" -n3="key3" \
  -o1="encrypted1" -o2="encrypted2" -o3="encrypted3"

# Encrypt all files in a directory with flags using comma-separated lists
qlock -e path-to-folder-with-three-files/ \
  -p "password1, password2, password3" \
  -n "key1, key2, key3" \
  -o "encrypted1, encrypted2, encrypted3"

# If you wind up with more files than passwords, outputs, or key names,
# you will be prompted for them while the command is running

# Decrypt all .qlock files in a directory with flags using numbered parameters
qlock -d path-to-folder-with-three-files/ \
  -p1="password1" -p2="password2" -p3="password3" \
  -o1="decrypted1" -o2="decrypted2" -o3="decrypted3"

# Decrypt all .qlock files in a directory with flags using comma-separated lists
qlock -d path-to-folder-with-three-files/ \
  -p "password1, password2, password3" \
  -o "decrypted1, decrypted2, decrypted3"
```

### Additional Options

```bash
# Auto-generate key names during encryption
qlock -e <file> -p <password> -a

# Force overwriting existing files automatically
qlock -e <file> -f
qlock -d <file> -f
```

### Output File Naming

- Without `-o`: Files are output next to the originals within the directory structure
  - Encryption: the original file name is used, but the file extension is replaced with `.qlock`
  - Decryption: we use the original file name saved in `qlock_metadata.json`
- With `-o`: Files are output in the directory you run this tool from
  - Encryption: The `.qlock` extension is added automatically, so no file extension is needed
  - Decryption: If you don't specify a file extension to -o, the original file's extension will be used (ex: using `-o "output"` and assuming the original file was a png, the decrypted file would be `output.png`)
  - Multiple files, but only one output name: A dash followed by a 4-digit counter is automatically appended to each file name, before the extension (ex: output-0000.qlock, output-0001.qlock, etc)

## Security Notes

- No security audit of this code has ever been performed
- Uses non-NIST based algorithms
- Passwords are never stored
- `qlock_metadata.json` contains sensitive data - avoid sharing or sending it over the network
- Losing passwords or your `qlock_metadata.json` file(s) means encrypted data cannot be recovered
- Consider using a password manager

## Technical Details

The encryption process:

1. Generates a unique random key for each file and uses it to encrypt the file's contents
2. Writes the encrypted contents to a new file with the `.qlock` extension
3. Derives a second key from a password you provide
4. Encrypts the first key using the password-derived key, and does not store the password-derived key
5. Stores each encrypted key and it's associated metadata in `qlock_metadata.json`

Stored metadata includes:

- Encrypted key
- A hash of the encrypted file contents
- Nonces and salts
- Input/output filenames
- Key name

## Roadmap

✓ Already Completed:

- [x] ~~add flags to provide a name or auto-generate one.~~
- [x] ~~add ability to list the details for a just one key, by name.~~
- [x] ~~add password flag, so you can skip all prompts.~~
- [x] ~~add support for folders during encryption/decryption.~~
- [x] ~~add -f --force-overwrite to skip the checks before overwriting files.~~
- [x] ~~add some tests.~~
- [x] ~~add support for multiple file inputs with per-file parameters (numbered or comma-separated).~~

Next Up:

- [ ] improve test coverage with more edge cases
- [ ] add tab auto-completion for key names
- [ ] add alternative encryption schemes:
  - focus on quantum-resistant algorithms
  - avoid NIST recommendations where possible
- [ ] expose customizable parameters for encryption/hashing algorithms
- [ ] support global metadata file in $HOME with path tracking
- [ ] integrate with password managers for automated password storage
- [ ] refine directory handling with per-file parameter support
- [ ] implement parallel processing for large files/directories
- [ ] add integrity verification commands
- [ ] support key rotation and metadata backup
