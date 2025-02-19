# qlock

**(pronounced 'Queue Lock', or 'clock' if ur feelin spicy?)**

A CLI tool written in Rust for encrypting files locally with XChaCha20Poly1305 and Argon2 hashing.

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
qlock -e <file path(s), or a directory>

# Decrypt file(s)
qlock -d <.qlock file path(s), or a directory containing .qlock files>

# List all encrypted keys
qlock ls

# List specific key
qlock ls <key name>

# Remove key metadata
qlock rm <key name>
```

### Multiple Files

You can encrypt/decrypt multiple files in two ways:

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

### Directory Encryption

```bash
# Encrypt all files in directory (ignores .qlock files and qlock_metadata.json)
qlock -e <folder>

# Decrypt all .qlock files in directory
qlock -d <folder>
```

### Additional Options

```bash
# Auto-generate key names
qlock -e <file> -p <password> -a

# Force overwrite without prompts
qlock -e <file> -f
```

### Output File Naming

- Without `-o`: Files are created next to originals
- With `-o`:
  - Encryption: `.qlock` extension is added automatically
  - Decryption: Specify desired extension in output name
  - Multiple files: 4-digit counter appended (e.g., output-0000.qlock)

## Security Notes

- Passwords are never stored
- `qlock_metadata.json` contains sensitive data - avoid network transmission
- Losing passwords or metadata file means encrypted data cannot be recovered
- Consider using a password manager

## Technical Details

The encryption process:

1. Generates the random key for file encryption
2. Derives a second key from a password you provide
3. Encrypts the first key with password-derived key
4. Stores each encrypted key and associated metadata in `qlock_metadata.json`

Stored metadata includes:

- Encrypted key
- File content hash
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
