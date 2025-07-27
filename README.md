# qlock 🪬

[![Rust](https://github.com/emmagamma/qlock/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/emmagamma/qlock/actions/workflows/rust.yml)

**(pronounced 'Queue Lock', or 'clock' if ur feelin spicy?)**

A CLI tool written in Rust for encrypting files locally using XChaCha20Poly1305 and Argon2 for key-derivation.

Use `qlock` to encrypt files before uploading them to cloud storage, backing up sensitive documents, or transferring data securely. It encrypts each file with a unique key, then encrypts that key using a password-derived key. The tool stores metadata neccessary to decrypt the resulting output `*.qlock` files in a folder named `.qlock_metadata/` in individual `.json` files for each file you encrypt.

> 🔐 You’ll need your password(s) for each file and each associated `.json` file in the `.qlock_metadata/` folder, in order to decrypt your `.qlock` files — be sure to save them securely.

---

## 🔧 Installation

### macOS – Using a Pre-compiled Binary

1. Download the appropriate macOS binary for your machine:

- [Download macOS Intel executable (x86_64)](https://github.com/emmagamma/qlock/releases/download/v0.5.0/qlock-darwin-x86_64.tar.gz)
- [Download macOS Apple Silicon executable (ARM)](https://github.com/emmagamma/qlock/releases/download/v0.5.0/qlock-darwin-ARM.tar.gz)

2. Unzip the downloaded file:

> Note: You can also just double-click the file to unzip it, and skip to step #3

```
# Change directory to your downloads folder (or wherever you saved it)
cd ./path-to-downloads

# Unzip the executable
tar -xvf qlock-darwin-x86_64.tar.gz
# Or, for Apple Silicon:
tar -xvf qlock-darwin-ARM.tar.gz
```

3. Move the executable into your local bin directory:

```
mv qlock-darwin-x86_64 /usr/local/bin/qlock
# Or
mv qlock-darwin-ARM /usr/local/bin/qlock
```

4. If macOS warns you about an unidentified developer, run:

```
xattr -dr com.apple.quarantine $(which qlock)
```

You should now be able to run `qlock` from your terminal.

---

### 🛠️ Linux / Windows / macOS – Building from Source

> If you don’t have `git`, install it from: [https://git-scm.com/downloads](https://git-scm.com/downloads)

> If you don’t have `cargo` installed, see: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)

1. Clone the repository and enter it:

```
git clone git@github.com:emmagamma/qlock.git && cd qlock/
```

2. Build and install using Cargo:

```
cargo build --release && cp target/release/qlock /usr/local/bin/qlock
```

You should now be able to run `qlock` from your terminal.

---

## 🔐 Usage

### 🔹 Encrypt a Single File

```
qlock -e myfile.txt -p "mypassword" -n "my-key-name"
```

### 🔹 Decrypt a Single File

```
qlock -d myfile.qlock -p "mypassword"
```

> 💡 `-n` or `--name` assigns a human-friendly name to your encrypted key (saved in `.qlock_metadata/`).

---

### 🔢 Encrypt/Decrypt Multiple Files with Flags

#### Method 1: Numbered Parameters

```
qlock -e file1.txt file2.txt \
  -p1="password1" -p2="password2" \
  -n1="key1" -n2="key2" \
  -o1="encrypted1" -o2="encrypted2"
```

```
qlock -d file1.qlock file2.qlock \
  -p1="password1" -p2="password2" \
  -o1="decrypted1.txt" -o2="decrypted2.txt"
```

#### Method 2: Comma-Separated Lists

```
qlock -e file1.txt file2.txt \
  -p "password1, password2" \
  -n "key1, key2" \
  -o "encrypted1, encrypted2"
```

```
qlock -d file1.qlock file2.qlock \
  -p "password1, password2" \
  -o "decrypted1.txt, decrypted2.txt"
```

---

### 🗂️ Encrypt or Decrypt All Files in a Folder (Recursively)

```
qlock -e ./path-to-folder/
qlock -d ./path-to-folder-with-qlock-files/
```

> ℹ️ If you don’t supply `-p` (password), `-n` (key name), or `-o` (output) flags for each file, `qlock` will prompt you **interactively** for them:
>
> - You'll be asked for a **password** and **key name** (when encrypting), or just a password (when decrypting)
> - If no output is specified, an **output name and location** will be chosen automatically based on [output naming rules](#-output-file-naming-rules)

---

### 🔍 Preview the Order that Files in a Folder will be Processed

When passing individual files to `qlock`, the order is obvious — it’s the order you provide them in. But when passing a **folder**, the internal file ordering is determined by how `qlock` recursively walks the directory.

If you're using **numbered flags** (like `-p1`, `-p2`, etc.) or **comma-separated lists** (like `-p "one, two, three"`) for multiple files, it's important to know **exactly which file each flag will apply to**.

To see the order `qlock` will use when processing files in a given folder, run:

```
qlock preview enc <folder>
qlock preview dec <folder>
```

**Example Output:**

```
1. path/some-image.png
2. path/some-text-file.txt
3. path/nested/another-file.js
```

Now you know that `-p1="first-password"` or the first password in a comma separated list- would apply to `some-image.png`, while `-p2="second-password"` or the second one in the list would apply to `some-text-file.txt`, and so on...

---

### 🧠 Managing Metadata

- List all stored keys:

```
qlock ls
```

- View a specific key’s metadata:

```
qlock ls <key name>
```

- Remove metadata for a specific key:

```
qlock rm <key name>
```

> ⚠️ Removing a key's metadata means you will no longer be able to decrypt the associated `.qlock` file — **even if you still have the `.qlock` file and the original password**.

---

### ⚙️ Additional Options

- `-a` or `--auto-name` to automatically generate key names:

```
qlock -e <file> -a
```

- `-f` or `--force-overwrite` to automatically force overwriting existing files:

```
qlock -e <file> -f
qlock -d <file> -f
```

---

### 📁 Output File Naming Rules

When you don’t provide `-o`/`--output`, output files are named and placed based on the original file paths and metadata. Here's how it works:

- **Without `-o`:** Files are output next to the originals within the directory structure.
  - **Encryption:** The original file name is used, but the file extension is replaced with `.qlock`
  - **Decryption:** The original file name (including extension) is restored using information stored in `.qlock_metadata/`

- **With `-o`:** Files are output in the directory you run the command from.
  - **Encryption:** The `.qlock` extension is added automatically — you don’t need to include one
  - **Decryption:**
    - If you **don’t** provide a file extension, the original file’s extension will be used
      - Example: `-o "output"` with an original `.png` file becomes `output.png`
    - If you **do** provide a file extension, it will be used **instead of** the original extension
      - Example: `-o "output.xyz"` with an original `.png` file becomes `output.xyz`
  - **Both Encryption and Decryption:** when passing **multiple files but only a single `-o` is specified**, a 4 digit counter will be added to the end of the file names:
    - Example: `output-0000.qlock`, `output-0001.qlock`, `output-0002.qlock`, etc...

---

## ⚠️ Security Notes

- No formal security audit of this repo has ever been performed
- Uses non-NIST algorithms
- Passwords are **never stored** by this tool
- `.qlock_metadata/` contains sensitive info that could be used in a brute-force attack to decrypt your `.qlock` files, given a powerful enough supercomputer — **don’t share it with anyone who shouldn't have access to your decrypted files**
- If you lose either your password or the `.json` files stored within the `.qlock_metadata/` folder, then the data in your `.qlock` files cannot be recovered
- Use a password manager to securely store your passwords

---

## 🔬 Technical Details

Encryption flow:

1. A random key is generated per file and used to encrypt the file contents
2. Encrypted content is saved with a `.qlock` extension
3. A second key is derived from your password using Argon2
4. The file key is encrypted with the password-derived key
5. The encrypted key and associated metadata are stored in `.qlock_metadata/`

> ℹ️ The password-derived key is never stored — and neither is your password. The ciphertext of the file key is stored, but not the file key itself. During decryption, qlock re-derives the password key on-the-fly using the password you provide. That key is then used to decrypt the file key (stored in `.qlock_metadata/`), which is finally used to decrypt the contents of your .qlock file.

Stored metadata includes:

- Encrypted key (the *ciphertext* of the key that was used to encrypt your files, not the key itself)
- Hash of the encrypted file contents
- Nonces and salts
- Input/output filenames
- Key name

---

## 📈 Roadmap

- [ ] Improve test coverage with edge cases
- [ ] Tab auto-completion for key names
- [ ] Support quantum-resistant encryption algorithms
- [ ] Allow customizing encryption/hashing parameters
- [ ] Global metadata file in `$HOME` with path tracking
- [ ] Password manager integration
- [ ] Refined per-file directory handling
- [ ] Parallel processing for large inputs
- [ ] Integrity verification commands
- [ ] Key rotation and metadata backup support

---

## 🍻 Support the Author

**Ko-fi:** https://ko-fi.com/emmagamma/tip

**BTC:**
```
0GkTcrxwSYiU8J9LH7akzi19PKGoLyHfzB
```

**ETH:**
```
0xf0173f53b85488ed9d085224612e7e04c7f4ab6b
```

**Monero:**
```
437xv9PdTTTiAGfjgN5H73JKpYzQnnqMSd96g9ijYfCxNMYJCdNjz2RHPz8iLcF36yLJuMJ9WWCGH1oWvmtK183t3rK9H4X
```
