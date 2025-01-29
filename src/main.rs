use argon2::Algorithm::Argon2d;
use argon2::Version::V0x13;
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use clap::{Parser, Subcommand};
use rand::RngCore;
use rpassword;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};


#[derive(Parser)]
#[command(author, version, about, long_about = Some("File encryption utility"))]
struct Qlock {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    action: Option<ActionArgs>,
}

#[derive(Parser)]
struct ActionArgs {
    /// The path to the file to encrypt or decrypt
    #[arg(value_parser = clap::value_parser!(PathBuf))]
    #[arg(required = false)]
    file: PathBuf,

    /// Encrypt the input file
    #[arg(short = 'e', long = "encrypt", group = "action")]
    encrypt: bool,

    /// Decrypt the input file
    #[arg(short = 'd', long = "decrypt", group = "action")]
    decrypt: bool,

    /// The name of the output file, when encrypting we will append .qlock, but when decrypting
    /// you can supply your own file extension. By default, if no output is specified, during
    /// encryption we use the name of the input file and replace the extension with .qlock, and
    /// during decryption we use the saved name of the original file, if found in
    /// qlock_metadata.json where your keys are saved in an encrypted format
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

#[derive(Debug)]
enum QlockError {
    IoError(io::Error),
    EncryptionError(String),
    DecryptionError(String),
    KeyDerivationError(String),
}

impl std::fmt::Display for QlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QlockError::IoError(err) => write!(f, "IO error: {}", err),
            QlockError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            QlockError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            QlockError::KeyDerivationError(msg) => write!(f, "Key derivation error: {}", msg),
        }
    }
}

impl std::error::Error for QlockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            QlockError::IoError(err) => Some(err),
            _ => None,
        }
    }
}

fn main() -> Result<(), QlockError> {
    let cli = Qlock::parse();

    match cli.command {
        Some(Commands::Ls) => {
            MetadataManager.list();
            return Ok(());
        }
        None => {}
    }

    if let Some(action) = cli.action {
        match (action.encrypt, action.decrypt) {
            (true, false) => {
                if let Err(e) = Encryptor::new().encrypt_file(&action.file, action.output) {
                    eprintln!("Encryption error: {:?}", e);
                }
            }
            (false, true) => {
                if let Err(e) = Decryptor::new().decrypt_file(&action.file, action.output) {
                    eprintln!("Decryption error: {:?}", e);
                }
            }
            _ => {
                eprintln!("Please specify either --encrypt or --decrypt");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

struct CryptoUtils {
    argon_params: argon2::Params,
}

impl CryptoUtils {
    fn new() -> Self {
        Self {
            argon_params: Params::new(42_699u32, 2u32, 8u32, Some(32)).unwrap(),
        }
    }

    fn generate_salt(&self) -> [u8; 16] {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        salt
    }

    fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<[u8; 32], QlockError> {
        let mut derived_key = [0u8; 32];
        Argon2::new(Argon2d, V0x13, self.argon_params.clone())
            .hash_password_into(password, salt, &mut derived_key)
            .map_err(|e| QlockError::KeyDerivationError(e.to_string()))?;
        Ok(derived_key)
    }

    fn generate_hash(&self, content: &[u8], salt: &[u8]) -> Result<[u8; 32], QlockError> {
        let mut hash = [0u8; 32];
        Argon2::new(Argon2d, V0x13, self.argon_params.clone())
            .hash_password_into(content, salt, &mut hash)
            .map_err(|e| QlockError::KeyDerivationError(e.to_string()))?;
        Ok(hash)
    }
}

struct FileUtils;

impl FileUtils {
    fn prompt_for_overwrite(path: &Path, operation: &str) -> bool {
        println!(
            "File {} already exists. Do you want to overwrite it with the {} contents? (y/n)",
            path.display(),
            operation
        );
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim() == "y"
    }

    fn write_with_confirmation(path: &Path, contents: &[u8], operation: &str) -> io::Result<()> {
        if path.exists() && !Self::prompt_for_overwrite(path, operation) {
            println!(
                "{} not modified\n\nNo {} data was output.",
                path.display(),
                operation
            );
            println!("If this was a mistake, you would need to run the command again and use `y` to overwrite the file.");
            return Ok(());
        }
        fs::write(path, contents)?;
        println!(
            "{} data was written to {} successfully",
            operation,
            path.display()
        );
        Ok(())
    }
}

struct MetadataManager;

impl MetadataManager {
    const METADATA_FILE: &'static str = "qlock_metadata.json";

    fn write(&self, additional_metadata: EncryptedData) -> io::Result<()> {
        if !Path::new(Self::METADATA_FILE).exists() {
            let empty = SavedData { data: vec![] };
            self.save_metadata(&empty)?;
        }

        let mut saved_data = self.read()?;
        saved_data.data.push(additional_metadata);
        self.save_metadata(&saved_data)?;
        println!("saved key metadata to: ./{}", Self::METADATA_FILE);
        Ok(())
    }

    fn read(&self) -> io::Result<SavedData> {
        if !Path::new(Self::METADATA_FILE).exists() {
            return Ok(SavedData { data: vec![] });
        }
        let metadata = fs::read_to_string(Self::METADATA_FILE)?;
        Ok(serde_json::from_str(&metadata)?)
    }

    fn save_metadata(&self, data: &SavedData) -> io::Result<()> {
        let serialized = serde_json::to_string(data)?;
        fs::write(Self::METADATA_FILE, serialized)
    }

    fn list(&self) {
        if !Path::new(Self::METADATA_FILE).exists() {
            println!("{} does not exist, try encrypting something first or make sure you're in the correct directory.", Self::METADATA_FILE);
            return;
        }

        match self.read() {
            Ok(saved_data) => {
                for datum in saved_data.data {
                    println!("hash: {:?}", datum.hash);
                    println!("  filename: {}", datum.filename);
                    println!("  encrypted output: {}", datum.output_filename);
                }
            }
            Err(e) => println!("Error reading metadata: {}", e),
        }
    }
}

struct Encryptor {
    crypto_utils: CryptoUtils,
}

impl Encryptor {
    fn new() -> Self {
        Self {
            crypto_utils: CryptoUtils::new(),
        }
    }

    fn encrypt_file(
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

    fn get_encryption_password(&self) -> Result<String, QlockError> {
        rpassword::prompt_password(
            "Don't forget to backup your password!\n\nIf you forget your password, you will not be able to decrypt your files!\n\n(min 16 chars, mix of upper + lower case, at least 1 number or special character)\nCreate a new password: "
        ).map_err(|e| QlockError::IoError(io::Error::new(io::ErrorKind::Other, e)))
    }

    fn encrypt_contents(
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

    fn determine_output_path(&self, file_path: &PathBuf, output_path: Option<String>) -> PathBuf {
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

    fn encrypt_key(
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

struct Decryptor {
    crypto_utils: CryptoUtils,
}

impl Decryptor {
    fn new() -> Self {
        Self {
            crypto_utils: CryptoUtils::new(),
        }
    }

    fn decrypt_file(
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

    fn verify_hash(&self, contents: &[u8], datum: &EncryptedData) -> Result<bool, QlockError> {
        let hash = self
            .crypto_utils
            .generate_hash(contents, &datum.hash_salt)?;
        Ok(hash.to_vec() == datum.hash)
    }

    fn get_decryption_password(&self) -> Result<String, QlockError> {
        rpassword::prompt_password("Enter password: ")
            .map_err(|e| QlockError::IoError(io::Error::new(io::ErrorKind::Other, e)))
    }

    fn decrypt_contents(
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
