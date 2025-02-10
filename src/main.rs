use clap::{Parser, Subcommand};
use std::path::PathBuf;

use qlock::crypto_utils::{Decryptor, Encryptor};
use qlock::metadata_manager::MetadataManager;
use qlock::qlock_errors::QlockError;

#[derive(Parser)]
#[command(author, version, about, long_about = Some("Encrypt/Decrypt files protected by a password"), override_usage = "qlock -e [FILE] [OPTIONS] || qlock -d [FILE] [OPTIONS] || qlock [COMMAND] [OPTIONS]")]
struct Qlock {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    action: Option<ActionArgs>,
}

#[derive(Parser, Clone)]
struct ActionArgs {
    /// The path of the file you want to encrypt or decrypt
    #[arg(value_parser = clap::value_parser!(PathBuf))]
    #[arg(required = false)]
    file: PathBuf,

    /// Encrypt a file
    #[arg(short = 'e', long = "encrypt", group = "action")]
    encrypt: bool,

    /// Decrypt a `.qlock` file
    #[arg(short = 'd', long = "decrypt", group = "action")]
    decrypt: bool,

    /// (Optional) What to name the output file during encryption and decryption.
    ///
    /// When encrypting, if output is not specified, the name of the file you're encrypting will be used,
    /// replacing the file extension with `.qlock`. However if an output *is* specified during
    /// encryption, any file extension(s) you include will be ignored and replaced with `.qlock`.
    /// When decrypting, if output is not provided, the original filename (saved in `qlock_metadata.json`)
    /// will be automatically used. However if an output *is* specified during decryption, you should include the
    /// file extension you want to use.
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// (Optional) the name to save your encrypted key with, in `qlock_metadata.json`.
    ///
    /// Only with -e or --encrypt, if name is not provided, you will be prompted for one.
    #[arg(short = 'n', long = "name")]
    name: Option<String>,

    /// (Optional) skip the prompt for a key name and auto-generate one instead.
    ///
    /// Only with -e or --encrypt, if -a or --auto-name is provided then -n (--name) will be ignored.
    #[arg(short = 'a', long = "auto-name")]
    auto_name: bool,

    /// (Optional) the password to encrypt your key with.
    ///
    /// If password is not provided, you will be prompted for one.
    ///
    /// It is recommended to use an environment variable and .env file, instead of typing it in
    /// plaintext on the command line.
    #[arg(short = 'p', long = "password")]
    password: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// List all encrypted keys saved in `qlock_metadata.json`, or use `qlock ls <key-name>` to just show one.
    Ls {
        /// The name of the encrypted key you want to list.
        #[arg(value_parser = clap::value_parser!(String))]
        key_name: Option<String>,
    },
    /// Remove an encrypted key from `qlock_metadata.json` by passing it's name `qlock rm <key-name>`.
    Rm {
        /// The name of the encrypted key to remove.
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
                if let Err(e) = Encryptor::new().encrypt_file_and_key(
                    &action.file,
                    action.output,
                    action.name,
                    action.auto_name,
                    action.password,
                ) {
                    eprintln!("{}", e.to_string());
                }
            }
            (false, true) => {
                if !action.name.is_none() {
                    eprintln!("-n or --name will be ignored, not needed during decryption");
                }
                if action.auto_name {
                    eprintln!("-a or --auto-name will be ignored, not needed during decryption");
                }
                if let Err(e) =
                    Decryptor::new().decrypt_file(&action.file, action.output, action.password)
                {
                    eprintln!("{}", e.to_string());
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
