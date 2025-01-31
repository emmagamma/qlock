use clap::{Parser, Subcommand};
use std::path::PathBuf;

use qlock::crypto_utils::{Decryptor, Encryptor};
use qlock::metadata_manager::MetadataManager;
use qlock::qlock_errors::QlockError;

#[derive(Parser)]
#[command(author, version, about, long_about = Some("File encryption utility"))]
struct Qlock {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    action: Option<ActionArgs>,
}

#[derive(Parser, Clone)]
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
    /// show a list of each encrypted key you have saved in `qlock_metadata.json`
    Ls,
    /// remove a saved encrypted key by passing it's name
    Rm {
        /// the name of the saved encrypted key to remove
        #[arg(value_parser = clap::value_parser!(String))]
        name: Option<String>,
    },
}

fn main() -> Result<(), QlockError> {
    let cli = Qlock::parse();

    match cli.command {
        Some(Commands::Ls) => {
            MetadataManager.list();
            return Ok(());
        }
        Some(Commands::Rm { name }) => {
            if !name.is_none() {
                if let Err(e) = MetadataManager.remove_metadata(&name.unwrap()) {
                    eprintln!("Error removing metadata: {}", e);
                }
            } else {
                eprintln!("Please specify the name of an encrypted key to remove");
            }
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
