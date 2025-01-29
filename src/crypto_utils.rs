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
use std::io::{self};
use std::path::{Path, PathBuf};

use crate::file_utils::FileUtils;
use crate::metadata_manager::{EncryptedData, MetadataManager};
use crate::qlock_errors::QlockError;

pub struct CryptoUtils {
    argon_params: argon2::Params,
}

impl CryptoUtils {
    pub fn new() -> Self {
        Self {
            argon_params: Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
        }
    }

    pub fn generate_salt(&self) -> [u8; 16] {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    }

    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<[u8; 32], QlockError> {
        let mut derived_key = [0u8; 32];
        Argon2::new(Argon2d, V0x13, self.argon_params.clone())
            .hash_password_into(password, salt, &mut derived_key)
            .map_err(|e| QlockError::KeyDerivationError(e.to_string()))?;
        Ok(derived_key)
    }

    pub fn generate_hash(&self, content: &[u8], salt: &[u8]) -> Result<[u8; 32], QlockError> {
        let mut hash = [0u8; 32];
        Argon2::new(Argon2d, V0x13, self.argon_params.clone())
            .hash_password_into(content, salt, &mut hash)
            .map_err(|e| QlockError::KeyDerivationError(e.to_string()))?;
        Ok(hash)
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

    pub fn encrypt_file(
        &self,
        file_path: &PathBuf,
        output_path: Option<String>,
    ) -> Result<(), QlockError> {
        let password = self.get_encryption_password()?;
        let contents = fs::read(file_path).map_err(QlockError::IoError)?;

        let (ciphertext, nonce_a, og_key) = self.encrypt_contents(&contents)?;
        let output_path = self.determine_output_path(file_path, output_path);

        let (encrypted_key, nonce_b, salt) = self.encrypt_key(&password, &og_key)?;
        let hash_salt = self.crypto_utils.generate_salt();
        let hash_bytes = self.crypto_utils.generate_hash(&ciphertext, &hash_salt)?;

        let metadata = EncryptedData {
            key: encrypted_key,
            hash: hash_bytes.to_vec(),
            nonce_a: nonce_a.to_vec(),
            nonce_b: nonce_b.to_vec(),
            salt: salt.to_vec(),
            hash_salt: hash_salt.to_vec(),
            filename: file_path.to_string_lossy().to_string(),
            output_filename: output_path.to_string_lossy().to_string(),
        };

        MetadataManager
            .write(metadata)
            .map_err(QlockError::IoError)?;
        FileUtils::write_with_confirmation(&output_path, &ciphertext, "encrypted")
            .map_err(QlockError::IoError)
    }

    pub fn get_encryption_password(&self) -> Result<String, QlockError> {
        rpassword::prompt_password(
            "Don't forget to backup your password!\n\nIf you forget your password, you will not be able to decrypt your files!\n\n(min 16 chars, mix of upper + lower case, at least 1 number or special character)\nCreate a new password: "
        ).map_err(|e| QlockError::IoError(io::Error::new(io::ErrorKind::Other, e)))
    }

    pub fn encrypt_contents(
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

    pub fn determine_output_path(&self, file_path: &PathBuf, output_path: Option<String>) -> PathBuf {
        match output_path {
            Some(path) => PathBuf::from([path, ".qlock".to_string()].join("")),
            None => PathBuf::from(
                [
                    file_path.file_stem().unwrap().to_str().unwrap().to_string(),
                    ".qlock".to_string(),
                ]
                .join(""),
            ),
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

    pub fn decrypt_file(
        &self,
        file_path: &PathBuf,
        output_path: Option<String>,
    ) -> Result<(), QlockError> {
        let contents = fs::read(file_path).map_err(QlockError::IoError)?;
        let saved = MetadataManager.read().map_err(QlockError::IoError)?;

        for datum in saved.data {
            if self.verify_hash(&contents, &datum)? {
                let filename = output_path.unwrap_or(datum.filename.clone());
                let password = self.get_decryption_password()?;

                let decrypted_contents = self.decrypt_contents(&password, &contents, &datum)?;
                return FileUtils::write_with_confirmation(
                    Path::new(&filename),
                    &decrypted_contents,
                    "decrypted",
                )
                .map_err(QlockError::IoError);
            }
        }

        println!(
            "no matching key found in {} for file: {}",
            MetadataManager::METADATA_FILE,
            file_path.display()
        );
        Ok(())
    }

    pub fn verify_hash(&self, contents: &[u8], datum: &EncryptedData) -> Result<bool, QlockError> {
        let hash = self
            .crypto_utils
            .generate_hash(contents, &datum.hash_salt)?;
        Ok(hash.to_vec() == datum.hash)
    }

    pub fn get_decryption_password(&self) -> Result<String, QlockError> {
        rpassword::prompt_password("Enter password: ")
            .map_err(|e| QlockError::IoError(io::Error::new(io::ErrorKind::Other, e)))
    }

    pub fn decrypt_contents(
        &self,
        password: &str,
        contents: &[u8],
        datum: &EncryptedData,
    ) -> Result<Vec<u8>, QlockError> {
        let derived_key = self
            .crypto_utils
            .derive_key(password.as_bytes(), &datum.salt)?;

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
