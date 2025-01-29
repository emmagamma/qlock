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

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = Some("things adn stufffffffff fffff fff f f f f f f ff f f ffffffff f "))]
struct Qlock {
    /// Commands
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    action: Option<ActionArgs>,
}

#[derive(Parser)]
struct ActionArgs {
    /// File to encrypt or decrypt
    #[arg(value_parser = clap::value_parser!(PathBuf))]
    #[arg(required = false)]
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

#[derive(Subcommand)]
enum Commands {
    /// list the hashes, input filename, and output filename, for each file you've already encrypted
    Ls,
}

#[derive(Serialize, Deserialize, Debug)]
struct EncryptedData {
    hash: Vec<u8>,
    key: Vec<u8>,
    nonce_a: Vec<u8>,
    nonce_b: Vec<u8>,
    salt: Vec<u8>,
    hash_salt: Vec<u8>,
    filename: String,
    output_filename: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SavedData {
    data: Vec<EncryptedData>,
}

fn main() -> std::io::Result<()> {
    let cli = Qlock::parse();

    match cli.command {
        Some(Commands::Ls) => {
            list_metadata();
            return Ok(());
        }
        None => {}
    }

    if let Some(action) = cli.action {
        match (action.encrypt, action.decrypt) {
            (true, false) => {
                encrypt_cmd(&action.file, action.output);
            }
            (false, true) => {
                decrypt_cmd(&action.file, action.output);
            }
            _ => {
                eprintln!("Please specify either --encrypt or --decrypt");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn encrypt_cmd(file_path: &PathBuf, output_path: Option<String>) {
    let prompt_text = "Don't forget to backup your password!\n\nIf you forget your password, you will not be able to decrypt your files!\n\n(min 16 chars, mix of upper + lower case, at least 1 number or special character)\nCreate a new password: ";
    let password = rpassword::prompt_password(prompt_text).unwrap();

    let contents = fs::read(file_path).expect("oops, couldn't read the file");

    let og_key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher_a = XChaCha20Poly1305::new(&og_key);
    let nonce_a = XChaCha20Poly1305::generate_nonce(&mut OsRng);

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

    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let mut derived_key = [0u8; 32];
    Argon2::new(
        Argon2d,
        V0x13,
        Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
    )
    .hash_password_into(&password.as_bytes(), &salt, &mut derived_key)
    .expect("Key derivation failed");

    let cipher_b = XChaCha20Poly1305::new((&derived_key).into());
    let nonce_b = XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let encrypted_key = cipher_b
        .encrypt(&nonce_b, og_key.as_ref())
        .expect("encryption failed");
 
    let mut hash_salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut hash_salt);
    let mut hash_bytes = [0u8; 32];
    Argon2::new(
        Argon2d,
        V0x13,
        Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
    )
    .hash_password_into(&ciphertext, &hash_salt, &mut hash_bytes)
    .expect("Hashing ciphertext failed");

    println!("hash of encrypted content: {:?}", hash_bytes);

    let encrypted_key = EncryptedData {
        key: encrypted_key,
        hash: hash_bytes.to_vec(),
        nonce_a: nonce_a.to_vec(),
        nonce_b: nonce_b.to_vec(),
        salt: salt.to_vec(),
        hash_salt: hash_salt.to_vec(),
        filename: file_path.to_string_lossy().to_string(),
        output_filename: output_path.to_string_lossy().to_string(),
    };

    write_metadata(encrypted_key);

    if Path::new(&output_path).exists() {
        println!(
            "File {} already exists. Do you want to overwrite it with the encrypted contents of {}? (y/n)",
            output_path.display(),
            file_path.display(),
        );
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        if input.trim() == "y" {
            fs::write(&output_path, &ciphertext).unwrap();
            println!(
                "output encrypted data to: {}",
                &output_path.to_string_lossy()
            );
            println!("{} was overwritten successfully", output_path.display());
            return;
        } else {
            println!("{} not modified\n\nno encrypted data was output.", file_path.display());
            println!("If this was a mistake, you would need to run the command again and use `y` to overwrite the file.");
            return;
        }
    } else {
        fs::write(&output_path, &ciphertext).unwrap();
        println!(
            "output encrypted data to: {}",
            &output_path.to_string_lossy()
        );
        println!("decrypted data was written to {} successfully", output_path.display());
        return;
    }
}

fn decrypt_cmd(file_path: &PathBuf, output_path: Option<String>) {
    let contents_vec = fs::read(file_path).unwrap();

    // 2. read the qlock_metadata.json file
    let saved = read_metadata();

    for datum in saved.data {
        let saved_hash = datum.hash;
        let hash_salt = datum.hash_salt;

        let mut hash_bytes = [0u8; 32];
        Argon2::new(
            Argon2d,
            V0x13,
            Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
        )
        .hash_password_into(&contents_vec, &hash_salt, &mut hash_bytes)
        .expect("Hashing ciphertext failed");

        if hash_bytes == *saved_hash {
            let key = datum.key;
            let salt = datum.salt;
            let nonce_a = XNonce::from_slice(&datum.nonce_a);
            let nonce_b = XNonce::from_slice(&datum.nonce_b);
            let filename: String = match output_path {
                Some(path) => path,
                None => datum.filename,
            };

            let password = rpassword::prompt_password("Enter password: ").unwrap();

            let mut derived_key = [0u8; 32];
            Argon2::new(
                Argon2d,
                V0x13,
                Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
            )
            .hash_password_into(&password.as_bytes(), &salt, &mut derived_key)
            .expect("Key derivation failed");

            let cipher_b = XChaCha20Poly1305::new((&derived_key).into());
            let decrypted_key = cipher_b.decrypt(nonce_b, &*key).expect("decryption failed");

            let cipher_a = XChaCha20Poly1305::new((&*decrypted_key).into());
            let decrypted_contents = cipher_a
                .decrypt(nonce_a, contents_vec.as_slice())
                .expect("decryption failed");

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
    if !Path::new("qlock_metadata.json").exists() {
        return SavedData { data: vec![] };
    }
    let metadata = fs::read_to_string("qlock_metadata.json").unwrap();
    let saved_data: SavedData = serde_json::from_str(&metadata).unwrap();
    saved_data
}

fn list_metadata() {
    if !Path::new("qlock_metadata.json").exists() {
        println!("qlock_metadata.json does not exist, try encrypting something first or make sure you're in the correct directory.");
        return;
    }
    let saved_data: SavedData = read_metadata();

    for datum in saved_data.data {
        println!("hash: {:?}", datum.hash);
        println!("  filename: {}", datum.filename);
        println!("  encrypted output: {}", datum.output_filename);
    }
}
