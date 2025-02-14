use argon2::Algorithm::Argon2d;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use rpassword;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;

use crate::file_utils::FileUtils;
use crate::metadata_manager::{EncryptedData, MetadataManager};
use crate::qlock_errors::QlockError;
use crate::word_lists::generate_random_name;

pub struct CryptoUtils {
    argon_params: argon2::Params,
}

impl CryptoUtils {
    pub fn new() -> Self {
        let num_threads: u32 = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .try_into()
            .unwrap();

        Self {
            argon_params: Params::new(42_699u32, 2u32, num_threads, Some(32)).unwrap(),
        }
    }

    pub fn generate_salt(&self) -> [u8; 16] {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    }

    pub fn generate_hash(&self, content: &[u8], salt: &[u8]) -> Result<[u8; 32], QlockError> {
        let mut hash = [0u8; 32];
        Argon2::new(Argon2d, V0x13, self.argon_params.clone())
            .hash_password_into(content, salt, &mut hash)
            .map_err(|e| QlockError::KeyDerivationError(e.to_string()))?;
        Ok(hash)
    }

    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<[u8; 32], QlockError> {
        let mut derived_key = [0u8; 32];
        Argon2::new(Argon2d, V0x13, self.argon_params.clone())
            .hash_password_into(password, salt, &mut derived_key)
            .map_err(|e| QlockError::KeyDerivationError(e.to_string()))?;
        Ok(derived_key)
    }
}

pub struct Encryptor {
    pub crypto_utils: CryptoUtils,
}

impl Encryptor {
    pub fn new() -> Self {
        Self {
            crypto_utils: CryptoUtils::new(),
        }
    }

    pub fn encrypt_dir(
        &self,
        file_path: &PathBuf,
        output_path: Option<String>,
        name: Option<String>,
        auto_gen_name: bool,
        password_flag: Option<String>,
        force: bool,
        mut index: u32,
    ) -> Result<(), QlockError> {
        let files = FileUtils::get_files_in_dir(file_path).unwrap();

        for file in files {
            let f = file.unwrap().path().clone();
            if f.is_dir() {
                if let Err(e) = self.encrypt_dir(
                    &f.to_path_buf(),
                    output_path.clone(),
                    name.clone(),
                    auto_gen_name,
                    password_flag.clone(),
                    force,
                    index,
                ) {
                    return Err(e);
                }
            } else {
                if f.extension().unwrap() != "qlock" && f.file_name().unwrap() != "qlock_metadata.json" {
                    let new_name = match name {
                        Some(ref n) => Some(format!("{}-{:04}", &n, index).to_string()),
                        None => None,
                    };
                    let new_output = match output_path {
                        Some(ref o) => {
                            let output_stem = &o.split(".").collect::<Vec<&str>>()[0];
                            Some(format!("{}-{:04}", &output_stem, index).to_string())
                        }
                        None => None,
                    };

                    println!("Encrypting contents of: {}", f.to_path_buf().display());
                    if let Err(e) = self.encrypt_file_and_key(
                        &f.to_path_buf(),
                        new_output,
                        new_name,
                        auto_gen_name,
                        password_flag.clone(),
                        force,
                    ) {
                        return Err(e);
                    } else {
                        index += 1;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn encrypt_file_and_key(
        &self,
        file_path: &PathBuf,
        output_path: Option<String>,
        name: Option<String>,
        auto_gen_name: bool,
        password_flag: Option<String>,
        force: bool,
    ) -> Result<(), QlockError> {
        let contents = fs::read(file_path).map_err(QlockError::IoError);
        if let Err(e) = contents {
            return Err(e);
        }

        let key_name = self.get_key_name(name, auto_gen_name);
        if let Err(e) = key_name {
            return Err(e);
        }

        let password;

        if let Some(pf) = password_flag {
            if validate_password(&pf) {
                password = pf;
            } else {
                std::process::exit(1);
            }
        } else {
            password = self.get_encryption_password_with("Don't forget to backup your password!\n\nIf you forget your password, you will not be able to decrypt your files!\n\n(min 16 chars, mix of upper + lower case, at least 1 number or special character)\nCreate a new password: ")?;
        }

        println!("Generating a random key and encrypting your data...");
        let (ciphertext, nonce_a, og_key) = self.encrypt_file_contents(&contents?)?;
        let output_path = self.determine_output_path(file_path, output_path);

        println!("Generating a password-derived key to encrypt the first key with...");
        let (encrypted_key, nonce_b, salt_a) = self.encrypt_key(&password, &og_key.to_vec())?;
        let salt_b = self.crypto_utils.generate_salt();
        let hash_bytes = self.crypto_utils.generate_hash(&ciphertext, &salt_b)?;

        let metadata = EncryptedData {
            name: key_name?,
            key: encrypted_key,
            hash: hash_bytes.to_vec(),
            nonce_a: nonce_a.to_vec(),
            nonce_b: nonce_b.to_vec(),
            salt_a: salt_a.to_vec(),
            salt_b: salt_b.to_vec(),
            input_filename: file_path.to_string_lossy().to_string(),
            output_filename: output_path.to_string_lossy().to_string(),
        };

        MetadataManager
            .write(metadata)
            .map_err(QlockError::IoError)?;
        FileUtils::write_with_confirmation(&output_path, &ciphertext, "Encrypted", force)
            .map_err(QlockError::IoError)
    }

    pub fn get_key_name(
        &self,
        provided_name: Option<String>,
        auto_gen_name: bool,
    ) -> Result<String, QlockError> {
        if !provided_name.is_none() {
            if MetadataManager.key_name_already_exists(&provided_name.clone().unwrap()) {
                return Err(QlockError::KeyAlreadyExists(provided_name.unwrap()));
            } else {
                if auto_gen_name {
                    println!(
                        "-a (--auto-name) is ignored because -n (--name) is already specified"
                    );
                }
                println!("Using key name: {}", provided_name.clone().unwrap());
                return Ok(provided_name.unwrap());
            }
        }

        if auto_gen_name {
            let name = generate_random_name();
            println!("Auto-generated name: {}", name);
            return Ok(name);
        }

        print!("Enter a name for your encrypted key (leave blank to auto-generate a name):");
        let _ = io::stdout().flush();

        let input = io::stdin();
        let mut key_name = String::new();
        input
            .read_line(&mut key_name)
            .map_err(QlockError::IoError)?;

        if key_name.trim().is_empty() {
            let name = generate_random_name();
            println!("Auto-generated name: {}", name);
            Ok(name)
        } else {
            if MetadataManager.key_name_already_exists(key_name.trim()) {
                return Err(QlockError::KeyAlreadyExists(key_name.trim().to_string()));
            }
            Ok(key_name.trim().to_string())
        }
    }

    pub fn get_encryption_password_with(&self, prompt: &str) -> Result<String, QlockError> {
        let pass = rpassword::prompt_password(prompt).map_err(|e| QlockError::IoError(e))?;

        if validate_password(&pass) {
            Ok(pass)
        } else {
            self.get_encryption_password_with("Create a new password: ")
        }
    }

    pub fn encrypt_file_contents(
        &self,
        contents: &[u8],
    ) -> Result<(Vec<u8>, XNonce, chacha20poly1305::Key), QlockError> {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = XChaCha20Poly1305::new(&key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, contents)
            .map_err(|e| QlockError::EncryptionError(e.to_string()))?;

        Ok((ciphertext, nonce, key))
    }

    pub fn determine_output_path(
        &self,
        file_path: &PathBuf,
        output_path: Option<String>,
    ) -> PathBuf {
        let parent_dir = file_path.parent().unwrap().to_string_lossy().to_string();
        let stem = file_path.file_stem().unwrap().to_str().unwrap().to_string();
        let fallback;

        if parent_dir.trim().is_empty() {
            fallback = [stem, ".qlock".to_string()].join("");
        } else {
            fallback = [parent_dir, "/".to_string(), stem, ".qlock".to_string()].join("");
        }

        match output_path {
            Some(path) => PathBuf::from([path, ".qlock".to_string()].join("")),
            None => PathBuf::from(fallback),
        }
    }

    pub fn encrypt_key(
        &self,
        password: &str,
        key: &[u8],
    ) -> Result<(Vec<u8>, XNonce, [u8; 16]), QlockError> {
        let salt = self.crypto_utils.generate_salt();
        let derived_key = self.crypto_utils.derive_key(password.as_bytes(), &salt)?;

        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let encrypted_key = cipher
            .encrypt(&nonce, key)
            .map_err(|e| QlockError::EncryptionError(e.to_string()))?;

        Ok((encrypted_key, nonce, salt))
    }
}

pub struct Decryptor {
    pub crypto_utils: CryptoUtils,
}

impl Decryptor {
    pub fn new() -> Self {
        Self {
            crypto_utils: CryptoUtils::new(),
        }
    }

    pub fn decrypt_dir(
        &self,
        file_path: &PathBuf,
        output_path: Option<String>,
        password_flag: Option<String>,
        force: bool,
        mut index: u32,
    ) -> Result<(), QlockError> {
        let files = FileUtils::get_files_in_dir(file_path).unwrap();

        for file in files {
            let f = file.unwrap().path().clone();
            if f.is_dir() {
                if let Err(e) = self.decrypt_dir(
                    &f.to_path_buf(),
                    output_path.clone(),
                    password_flag.clone(),
                    force,
                    index,
                ) {
                    return Err(e);
                }
            } else {
                if f.extension().unwrap() == "qlock" {
                    let new_output = match output_path {
                        Some(ref o) => {
                            if o.contains(".") {
                                let output_stem = &o.split(".").collect::<Vec<&str>>()[0];
                                let output_extension = &o.split(".").collect::<Vec<&str>>()[1];

                                Some(
                                    format!("{}-{:04}.{}", &output_stem, index, output_extension).to_string(),
                                )
                            } else {
                                Some(format!("{}-{:04}", &o, index).to_string())
                            }
                        }
                        None => None,
                    };

                    println!("Decrypting file: {}", f.display());
                    if let Err(e) = self.decrypt_key_and_file(
                        &f.to_path_buf(),
                        new_output,
                        password_flag.clone(),
                        force,
                    ) {
                        return Err(e);
                    } else {
                        index += 1;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn decrypt_key_and_file(
        &self,
        file_path: &PathBuf,
        output_path: Option<String>,
        password_flag: Option<String>,
        force: bool,
    ) -> Result<(), QlockError> {
        let contents = fs::read(file_path).map_err(QlockError::IoError)?;
        let saved = MetadataManager.read().map_err(QlockError::IoError)?;

        for datum in saved.data {
            if self.verify_hash(&contents, &datum)? {
                let filename = output_path.unwrap_or(datum.input_filename.clone());
                let password;

                if let Some(pf) = password_flag {
                    password = pf;
                } else {
                    password = self.get_decryption_password()?;
                }

                let decrypted_contents =
                    self.decrypt_file_contents(&password, &contents, &datum)?;
                return FileUtils::write_with_confirmation(
                    Path::new(&filename),
                    &decrypted_contents,
                    "Decrypted",
                    force,
                )
                .map_err(QlockError::IoError);
            }
        }

        println!(
            "no matching key found in '{}' for file: '{}'",
            MetadataManager::METADATA_FILE,
            file_path.display()
        );
        Ok(())
    }

    pub fn verify_hash(&self, contents: &[u8], datum: &EncryptedData) -> Result<bool, QlockError> {
        let hash = self
            .crypto_utils
            .generate_hash(contents, &datum.salt_b)?;
        Ok(hash.to_vec() == datum.hash)
    }

    pub fn get_decryption_password(&self) -> Result<String, QlockError> {
        rpassword::prompt_password("Enter password: ")
            .map_err(|e| QlockError::IoError(io::Error::new(io::ErrorKind::Other, e)))
    }

    pub fn decrypt_file_contents(
        &self,
        password: &str,
        contents: &[u8],
        datum: &EncryptedData,
    ) -> Result<Vec<u8>, QlockError> {
        let derived_key = self
            .crypto_utils
            .derive_key(password.as_bytes(), &datum.salt_a)?;

        let cipher_b = XChaCha20Poly1305::new((&derived_key).into());
        let nonce_b = XNonce::from_slice(&datum.nonce_b);

        let decrypted_key = cipher_b
            .decrypt(nonce_b, &*datum.key)
            .map_err(|e| QlockError::DecryptionError(e.to_string()))?;

        let cipher_a = XChaCha20Poly1305::new((&*decrypted_key).into());
        let nonce_a = XNonce::from_slice(&datum.nonce_a);

        cipher_a
            .decrypt(nonce_a, contents)
            .map_err(|e| QlockError::DecryptionError(e.to_string()))
    }
}

fn validate_password(password: &str) -> bool {
    let has_number_or_punctuation = password
        .chars()
        .any(|c| c.is_ascii_punctuation() || c.is_numeric());
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());

    if password.len() < 16 {
        eprintln!("Password was too short, it should be at least 16 characters long...");

        if !has_uppercase || !has_lowercase {
            eprintln!("It should also contain a mix of upper and lower case letters");

            if !has_number_or_punctuation {
                eprintln!("and at least 1 number or special character");
            }
        } else if !has_number_or_punctuation {
            eprintln!("It should also contain at least 1 number or special character\n");
        }

        eprintln!("Let's try again");

        return false;
    }

    if !has_uppercase || !has_lowercase {
        eprintln!("Passwords should contain a mix of upper and lower case characters...\n");

        if !has_number_or_punctuation {
            eprintln!("It was also missing at least 1 number or special character\n");
        }

        eprintln!("Let's try again");

        return false;
    }

    if !has_number_or_punctuation {
        eprintln!(
            "Password was missing at least 1 number or special character...\n\nLet's try again"
        );
        return false;
    }

    true
}
