use clap::{Parser, Subcommand};
use std::path::PathBuf;

use qlock::crypto_utils::{Decryptor, Encryptor};
use qlock::metadata_manager::MetadataManager;
use qlock::qlock_errors::QlockError;

#[derive(Parser)]
#[command(author, version, about, long_about = Some("Encrypt/Decrypt files protected by a password"), override_usage = "qlock -e [FILE] [OPTIONS] || qlock -d [FILE] [OPTIONS] || qlock [COMMAND] [ARGS]")]
struct Qlock {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    action: Option<ActionArgs>,
}

#[derive(Parser, Clone)]
struct ActionArgs {
    /// The path of the file or folder you want to encrypt or decrypt
    #[arg(value_parser = clap::value_parser!(PathBuf), required = false)]
    file: PathBuf,

    /// Encrypt a file, or all files within a folder recursively (excluding those ending in `.qlock`)
    #[arg(short = 'e', long = "encrypt", group = "action")]
    encrypt: bool,

    /// Decrypt a `.qlock` file, or all `.qlock` files within a folder recursively
    #[arg(short = 'd', long = "decrypt", group = "action")]
    decrypt: bool,

    /// (Optional) the password to encrypt your key with. If password is not provided, you will be prompted for one
    ///
    /// It is recommended to use an environment variable and .env file, instead of typing it in
    /// plaintext on the command line
    #[arg(short = 'p', long = "password", required = false)]
    password: Option<String>,

    /// (Optional) What to name the output file during encryption or decryption
    ///
    /// When encrypting/decrypting all files within a folder, an auto-incrementing 4 digit counter
    /// will be appended before the file extension
    #[arg(short = 'o', long = "output", required = false)]
    output: Option<String>,

    /// (Optional) the name to save your encrypted key with, in `qlock_metadata.json`. Only with -e
    /// or --encrypt
    ///
    /// When encrypting all files within a folder, an auto-incrementing 4 digit counter will be appended to the end
    #[arg(short = 'n', long = "name", required = false)]
    name: Option<String>,

    /// (Optional) skip the prompt for a key name and auto-generate one instead. Only with -e or
    /// --encrypt
    ///
    /// If -n (--name) is provided, this will be ignored and we'll use the provided name
    #[arg(short = 'a', long = "auto-name", required = false)]
    auto_name: bool,

    /// (Optional) when provided, will skip (y/n) prompts and automatically overwrite existing files
    #[arg(short = 'f', long = "force-overwrite", required = false)]
    force: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// List all encrypted keys saved in `qlock_metadata.json`, or use `qlock ls <key-name>` to just show one
    Ls {
        /// The name of the encrypted key you want to list
        #[arg(value_parser = clap::value_parser!(String))]
        key_name: Option<String>,
    },
    /// Remove an encrypted key from `qlock_metadata.json` by passing it's name `qlock rm <key-name>`
    Rm {
        /// The name of the encrypted key to remove
        #[arg(value_parser = clap::value_parser!(String))]
        key_name: Option<String>,
    },
}

fn main() -> Result<(), QlockError> {
    let cli = Qlock::parse();

    match cli.command {
        Some(Commands::Ls { key_name }) => {
            MetadataManager.list(key_name);
            return Ok(());
        }
        Some(Commands::Rm { key_name }) => {
            if key_name.is_none() {
                eprintln!("Please specify the name of an encrypted key to remove...");
                println!("(try `qlock ls` to see them all)");
                std::process::exit(1);
            } else {
                if let Err(e) = MetadataManager.remove_metadata(&key_name.unwrap()) {
                    eprintln!("{}", e.to_string());
                }
            }
            return Ok(());
        }
        None => {}
    }

    if let Some(action) = cli.action {
        match (action.encrypt, action.decrypt) {
            (true, false) => {
                if action.file.is_dir() {
                    if let Err(e) = Encryptor::new().encrypt_dir(
                        &action.file,
                        action.output.clone(),
                        action.name.clone(),
                        action.auto_name,
                        action.password.clone(),
                        action.force,
                        0,
                    ) {
                        eprintln!("{}", e.to_string());
                    }
                } else {
                    if let Err(e) = Encryptor::new().encrypt_file_and_key(
                        &action.file,
                        action.output,
                        action.name,
                        action.auto_name,
                        action.password,
                        action.force,
                    ) {
                        eprintln!("{}", e.to_string());
                    }
                }
            }
            (false, true) => {
                if !action.name.is_none() {
                    eprintln!("-n or --name will be ignored, not needed during decryption");
                }
                if action.auto_name {
                    eprintln!("-a or --auto-name will be ignored, not needed during decryption");
                }

                if action.file.is_dir() {
                    if let Err(e) = Decryptor::new().decrypt_dir(
                        &action.file,
                        action.output.clone(),
                        action.password.clone(),
                        action.force,
                        0,
                    ) {
                        eprintln!("{}", e.to_string());
                    }
                } else {
                    if let Err(e) = Decryptor::new().decrypt_key_and_file(
                        &action.file,
                        action.output,
                        action.password,
                        action.force,
                    ) {
                        eprintln!("{}", e.to_string());
                    }
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
