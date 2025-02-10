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

The basics:
```bash
# encrypt a file
qlock -e <file path>

# decrypt the encrypted file
qlock -d <path to .qlock file>

# list out all encrypted keys with some metadata
qlock ls

# remove all the saved metadata for a given key, by name
qlock rm <key name>
```

Specify an output file name:
```bash
# specify an optional output to name the encrypted file, note that `.qlock` will be appended to it automatically.
# if no output name is provided, we use the original file name with `.qlock` instead of it's original extension.
qlock -e <file path> -o <output file name>

# specify an optional output to name the decrypted file, including the file extension to use.
# if no output name is provided, we use the original file name saved in `qlock_metadata.json` from when the file was encrypted.
qlock -d <path to .qlock file> -o <output file name>
```

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

- [x] add flags to provide a name or auto-generate one.
- [x] add ability to list the details for a just one key, by name.
- [x] add password flag, so you can skip all prompts.
- [ ] add some tests.
- [ ] add support for multiple files, and folders.
- [ ] add tab auto-complete for key names.
- [ ] add support for other encryption schemes and hashing algorithms.
  - ideally ones that are resistant to quantum attacks, and not based on NIST recommendations.
- [ ] allow users to customize the parameters of the encryption and hashing algorithms where appropriate.
- [ ] (maybe) make `qlock_metadata.json` global by moving it to `$HOME/` and include path details in `EncryptedData`.
- [ ] (maybe) add integration with a few popular password managers to automatically save passwords.
- [ ] figure out what else is next.
