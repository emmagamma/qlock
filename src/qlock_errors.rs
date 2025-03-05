use std::io::{self};

#[derive(Debug)]
pub enum QlockError {
    IoError(io::Error),
    EncryptionError(String),
    DecryptionError(String),
    KeyDerivationError(String),
    MetadataNotFound(String),
    KeyAlreadyExists(String),
}

impl From<io::Error> for QlockError {
    fn from(error: io::Error) -> Self {
        QlockError::IoError(error)
    }
}

impl std::fmt::Display for QlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QlockError::IoError(err) => write!(f, "IO error: {}", err),
            QlockError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            QlockError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            QlockError::KeyDerivationError(msg) => write!(f, "Key derivation error: {}", msg),
            QlockError::MetadataNotFound(msg) => write!(f, "Metadata not found for: {}", msg),
            QlockError::KeyAlreadyExists(msg) => write!(
                f,
                "A key named '{}' already exists, please choose a different name...",
                msg
            ),
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
