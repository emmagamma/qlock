# qlock

**(pronounced 'Queue Lock', or 'clock' if ur feelin spicy?)**

a simple CLI tool written in rust for encrypting files locally with XChaCha20Poly1305, and using argon2 for hashing.

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

Encrypt/Decrypt a file:
```bash
# encrypt a file
qlock -e <file path>

# decrypt the encrypted file
qlock -d <path to .qlock file>
```

Encrypt/Decrypt a folder recursively:
```bash
# encrypt a folder, ignores all `.qlock` files and `qlock_metadata.json`
qlock -e <path to folder>

# decrypt the encrypted folder, only decrypts files ending in `.qlock`
qlock -d <path to folder>
```

List or remove saved keys and metadata:
```bash
# list out all encrypted keys with some metadata
qlock ls

# remove all the saved metadata for a given key, by name
qlock rm <key name>
```

Specify an output file name:
```bash
# specify an optional output to name the encrypted file(s)
# any file extension you specify will be ignored, and `.qlock` will be used instead
# if no output name is provided, we use the original file name with `.qlock` as the extension
qlock -e <file or folder path> -o <output file name>

# specify an optional output to name the decrypted file(s), *including* the file extension to use.
# if no output name is provided, we use the original file name saved in `qlock_metadata.json`.
qlock -d <path to .qlock file, or folder> -o <output file name>
```

> Note: When specifying an output, an auto-incrementing 4 digit counter will be appended to each file name.
> So using `qlock -e <path> -o output` with a folder containing 3 files would yield: `output-0000.qlock`, `output-0001.qlock`, and `output-0002.qlock`.
> This also means that specifying an output forces files to be output flatly in whichever directory you run this tool from.
> When no output is specified, during encryption `.qlock` files are generated next to the originals within the folder structure, and the decrypted output files are put back into the original file locations using the original file names.

Skip the prompts:
```bash
# pass a specific name and password
qlock -e <file path> -n <key name> -p <your password>

# auto-generate the name, and specify a password
qlock -e <file path> -p <your password> -a
qlock -e <file path> -p <your password> --auto-name
```

> Note: When using the -p flag, your password would be printed to the terminal and possibly saved in your bash history.
> If you want to avoid that, use an .env file or similar solution so you can pass the environment variable instead.

Encrypt/Decrypt a folder recursively:
```bash
qlock -e <path to folder>
qlock -d <path to folder>
```

> Note: When encrypting, and passing an output and name for the key, an auto-incrementing 4 digit counter will be appended to each.
> When decrypting, and passing an output, an auto-incrementing 4 digit counter will be appended before the file extension.
> Also, during encryption we automatically ignore all `.qlock` files, and during decryption we only decrypt files ending in `.qlock`.

### Nerdy Details

The way it works is by first generating a random key to encrypt the contents of your file,
then we use a password you create to derive a second key which is used to encrypt the first key,
we do not store the password-derived key, only an encrypted version of the first key.
Metadata about each encrypted key is saved in a file called `qlock_metadata.json` in whichever directory you run this tool from,
including a hash of the encrypted contents of the file, the encrypted version of the first key,
two nonces, two salts, the input filename and output filename, and a user-provided or auto-generated name.

> Since we don't store the password itself or anything based on it, forgetting your password(s)
> will result in you no longer being able to decrypt your `.qlock` file(s). I recommend using a password manager.

> Even if you remember your password, accidentally deleting your `qlock_metadata.json` file, or using `qlock rm <key name>` to remove a given key
> will result in you no longer being able to decrypt your `.qlock` file(s).

> The `qlock_metadata.json` file contains sensitive information, I strongly recommend against sending it over any networks or saving it to the cloud without first encrypting it.

### Roadmap

- [x] ~~add flags to provide a name or auto-generate one.~~
- [x] ~~add ability to list the details for a just one key, by name.~~
- [x] ~~add password flag, so you can skip all prompts.~~
- [x] ~~add support for folders during encryption/decryption.~~
- [x] ~~add -f --force-overwrite to skip the checks before overwriting files.~~
- [x] ~~add some tests.~~
- [ ] improve tests with more edge cases.
- [ ] add support for passing a list of files to encrypt/decrypt (rather than pointing to a folder).
- [ ] add ability to specify different names, passwords, and outputs for each file, when pointing to a folder or passing a list of files.
- [ ] add tab auto-complete for key names.
- [ ] add support for other encryption schemes and hashing algorithms.
  - ideally ones that are resistant to quantum attacks, and not based on NIST recommendations.
- [ ] allow users to customize the parameters of the encryption and hashing algorithms where appropriate.
- [ ] (maybe) make `qlock_metadata.json` global by moving it to `$HOME/` and include path details in `EncryptedData`.
- [ ] (maybe) add integration with a few popular password managers to automatically save passwords.
- [ ] figure out what else is next.
