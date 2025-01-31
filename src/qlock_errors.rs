use std::io::{self};

#[derive(Debug)]
pub enum QlockError {
    IoError(io::Error),
    EncryptionError(String),
    DecryptionError(String),
    KeyDerivationError(String),
    MetadataNotFound(String),
}

impl std::fmt::Display for QlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QlockError::IoError(err) => write!(f, "IO error: {}", err),
            QlockError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            QlockError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            QlockError::KeyDerivationError(msg) => write!(f, "Key derivation error: {}", msg),
            QlockError::MetadataNotFound(msg) => write!(f, "Metadata not found: {}", msg),
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
