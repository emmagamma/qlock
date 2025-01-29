use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use rand::RngCore;

use rpassword;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};

use argon2::Algorithm::Argon2d;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};

use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = Some("things adn stufffffffff fffff fff f f f f f f ff f f ffffffff f "))]
struct Qlock {
    /// File to encrypt or decrypt
    #[arg(value_parser = clap::value_parser!(PathBuf))]
    file: PathBuf,

    /// Encrypt the input file
    #[arg(short = 'e', long = "encrypt", group = "action")]
    encrypt: bool,

    /// Decrypt the input file
    #[arg(short = 'd', long = "decrypt", group = "action")]
    decrypt: bool,

    /// Output file name (optional)
    #[arg(short = 'o', long = "output")]
    output: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedData {
    hash: Vec<u8>,
    key: Vec<u8>,
    nonce_a: Vec<u8>,
    nonce_b: Vec<u8>,
    salt: Vec<u8>,
    filename: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SavedData {
    data: Vec<EncryptedData>,
}

fn main() -> std::io::Result<()> {
    let cli = Qlock::parse();

    if cli.encrypt {
        encrypt_cmd(&cli.file, cli.output);
    } else if cli.decrypt {
        decrypt_cmd(&cli.file, cli.output);
    } else {
        eprintln!("Please specify either --encrypt or --decrypt");
        std::process::exit(1);
    }

    Ok(())
}

fn encrypt_cmd(file_path: &PathBuf, output_path: Option<String>) {
    // 1. prompt the user for a password
    let prompt_text = "Don't forget to backup your password!\n\nIf you forget your password, you will not be able to decrypt your files!\n\n(min 16 chars, mix of upper + lower case, at least 1 number or special character)\nCreate a new password: ";
    let password = rpassword::prompt_password(prompt_text).unwrap();

    // 2. get the contents of the file at the provided file path
    let contents = fs::read(file_path).expect("oops, couldn't read the file");

    // 3. generate a key
    let og_key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher_a = XChaCha20Poly1305::new(&og_key);
    let nonce_a = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    // 4. encrypt the contents of the file
    let ciphertext = cipher_a
        .encrypt(&nonce_a, contents.as_slice())
        .expect("encryption failed");

    let default_output_filename: String = [
        file_path.file_stem().unwrap().to_str().unwrap().to_string(),
        ".qlock".to_string(),
    ]
    .join("");
    let output_path = match output_path {
        Some(path) => PathBuf::from([path, ".qlock".to_string()].join("")),
        None => PathBuf::from(default_output_filename),
    };

    // 5. generate a random salt
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    // 6. use the provided password and random salt to generate a derived key
    let mut derived_key = [0u8; 32];
    Argon2::new(
        Argon2d,
        V0x13,
        Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
    )
    .hash_password_into(&password.as_bytes(), &salt, &mut derived_key)
    .expect("Key derivation failed");

    // 7. encrypt the og_key using the password-derived key
    let cipher_b = XChaCha20Poly1305::new((&derived_key).into());
    let nonce_b = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let encrypted_key = cipher_b
        .encrypt(&nonce_b, og_key.as_ref())
        .expect("encryption failed");

    let mut hash_bytes = [0u8; 32];
    Argon2::new(
        Argon2d,
        V0x13,
        Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
    )
    .hash_password_into(&ciphertext, &salt, &mut hash_bytes)
    .expect("Hashing ciphertext failed");

    println!("hash of encrypted content: {:?}", hash_bytes);

    // 8. use serde to serialize an instance of EncryptedData
    let encrypted_key = EncryptedData {
        key: encrypted_key,
        hash: hash_bytes.to_vec(),
        nonce_a: nonce_a.to_vec(),
        nonce_b: nonce_b.to_vec(),
        salt: salt.to_vec(),
        filename: file_path.to_string_lossy().to_string(),
    };

    write_metadata(encrypted_key);

    // 9. write the encrypted contents to the output file
    fs::write(&output_path, &ciphertext).unwrap();
    println!(
        "output encrypted data to: {}",
        &output_path.to_string_lossy()
    );

    // 10. buncha logging
    // println!("og key generated: {:?}", og_key);
    // println!("nonce a generated: {:?}", nonce_a);

    // println!(
    //     "ciphertext from file contents using og_key and nonce: {:?}",
    //     ciphertext
    // );

    // println!("salt generated: {:?}", salt);
    // println!("password provided: {:?}", password);
    // println!("derived key: {:?}", derived_key);
    // println!("nonce b generated: {:?}", nonce_b);

    // println!("encrypted key: {:?}", encrypted_key);
}

fn decrypt_cmd(file_path: &PathBuf, output_path: Option<String>) {
    // 1. get the contents of the file as an array of bytes
    let contents_vec = fs::read(file_path).unwrap();

    // 2. read the qlock_metadata.json file
    let saved = read_metadata();

    for datum in saved.data {
        let saved_hash = datum.hash;
        let salt = datum.salt;

        let mut hash_bytes = [0u8; 32];
        Argon2::new(
            Argon2d,
            V0x13,
            Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
        )
        .hash_password_into(&contents_vec, &salt, &mut hash_bytes)
        .expect("Hashing ciphertext failed");

        if hash_bytes == *saved_hash {
            let key = datum.key;
            let nonce_a = XNonce::from_slice(&datum.nonce_a);
            let nonce_b = XNonce::from_slice(&datum.nonce_b);
            let filename: String = match output_path {
                Some(path) => path,
                None => datum.filename,
            };

            // 4. use the salt and password to generate a derived key
            let password = rpassword::prompt_password("Enter password: ").unwrap();

            let mut derived_key = [0u8; 32];
            Argon2::new(
                Argon2d,
                V0x13,
                Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
            )
            .hash_password_into(&password.as_bytes(), &salt, &mut derived_key)
            .expect("Key derivation failed");

            // 5. decrypt the encrypted key using the derived key
            let cipher_b = XChaCha20Poly1305::new((&derived_key).into());
            let decrypted_key = cipher_b.decrypt(nonce_b, &*key).expect("decryption failed");

            // 6. decrypt the contents of the file using the decrypted key
            let cipher_a = XChaCha20Poly1305::new((&*decrypted_key).into());
            let decrypted_contents = cipher_a
                .decrypt(nonce_a, contents_vec.as_slice())
                .expect("decryption failed");

            println!(
                "decrypted contents: {:?}",
                String::from_utf8_lossy(&decrypted_contents)
            );

            // 7. write the decrypted contents to a file with the original filename
            //    - if the file already exists, ask the user if they want to overwrite it
            //    - otherwise, just write the file and let them know the results.
            if Path::new(&filename).exists() {
                println!(
                    "File {} already exists. Do you want to overwrite it with the decrypted contents of {}? (y/n)",
                    filename,
                    file_path.display()
                );
                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();
                if input.trim() == "y" {
                    fs::write(&filename, &decrypted_contents).unwrap();
                    println!("{} was overwritten successfully", filename);
                    return;
                } else {
                    println!("{} not modified\n\nno decrypted data was output.", filename);
                    println!("If this was a mistake, you would need to run the command again and use `y` to overwrite the file.");
                    return;
                }
            } else {
                fs::write(&filename, &decrypted_contents).unwrap();
                println!("decrypted data was written to {} successfully", filename);
                return;
            }
        }
    }

    println!(
        "no matching key found in qlock_metadata.json for file: {}",
        file_path.display()
    );
    return;
}

fn write_metadata(additional_metadata: EncryptedData) {
    if !Path::new("qlock_metadata.json").exists() {
        fs::File::create("qlock_metadata.json").unwrap();
        let empty = serde_json::to_string(&SavedData { data: vec![] }).unwrap();
        fs::write("qlock_metadata.json", empty).unwrap();
    }

    let saved_data: SavedData = read_metadata();

    let mut new_data = saved_data.data;
    new_data.push(additional_metadata);
    let serialized = serde_json::to_string(&SavedData { data: new_data }).unwrap();

    fs::write("qlock_metadata.json", serialized).unwrap();
    println!("saved key metadata to: ./qlock_metadata.json");
}

fn read_metadata() -> SavedData {
    let metadata = fs::read_to_string("qlock_metadata.json").unwrap();
    let saved_data: SavedData = serde_json::from_str(&metadata).unwrap();
    saved_data
}
