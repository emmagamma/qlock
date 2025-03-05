use clap::{Parser, Subcommand};
use std::path::PathBuf;

use qlock::crypto_utils::{Decryptor, Encryptor};
use qlock::file_utils::FileUtils;
use qlock::metadata_manager::MetadataManager;
use qlock::qlock_errors::QlockError;

#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = Some("Encrypt/Decrypt files protected by a password"),
    override_usage = "\
       # Single File:
       qlock -e <FILE>
       qlock -d <FILE.qlock>

       # Multiple Files, with flags to skip the prompts:
       qlock -e <FILE-1> <FILE-2> -p1=\"pass1\" -p2=\"pass2\" -n1=\"key1\" -n2=\"key2\" -o1=\"out1\" -o2=\"out2\"
       qlock -e <FILE-1> <FILE-2> -p \"pass1, pass2\" -n \"key1, key2\" -o \"encrypted-1, encrypted-2\"
       qlock -d <FILE-1.qlock> <FILE-2.qlock> -p1=\"pass1\" -p2=\"pass2\" -o1=\"decrypted-1.md\" -o2=\"decrypted-2.js\"
       qlock -d <FILE-1.qlock> <FILE-2.qlock> -p \"pass1, pass2\" -o \"decrypted-1.jpeg, decrypted-2.jpeg\"

       # All files within a directory, recursively (ignores all `.qlock` files and `qlock_metadata.json`):
       qlock -e <Folder>
       qlock -d <Folder>"
)]
struct Qlock {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    action: Option<ActionArgs>,
}

#[derive(Parser, Clone)]
struct ActionArgs {
    /// A File, multiple files, or a directory to encrypt/decrypt. For multiple files, separate with spaces
    #[arg(value_parser = clap::value_parser!(PathBuf), required = false, num_args = 1..)]
    files: Vec<PathBuf>,

    /// Encrypt a file, multiple files, or all files within a folder recursively (excluding those ending in `.qlock`, and `qlock_metadata.json`)
    #[arg(short = 'e', long = "encrypt", group = "action")]
    encrypt: bool,

    /// Decrypt a `.qlock` file, multiple `.qlock` files, or all `.qlock` files within a folder recursively
    #[arg(short = 'd', long = "decrypt", group = "action")]
    decrypt: bool,

    /// Password(s) for each file.
    ///
    /// Can be specified as:
    /// 1. A single string: -p "password"
    /// 2. A comma-separated list: -p "pass1, pass2, pass3"
    /// 3. Numbered flags: -p1="pass1" -p2="pass2" -p3="pass3"
    ///    (To include commas in a password, just escape them: `-p "pass1, pass2\,With\,Commas, pass3"`)
    #[arg(
        short = 'p',
        long = "password",
        required = false,
        value_parser = parse_numbered_or_list,
        num_args = 1..,
    )]
    password: Vec<String>,

    /// Output filename(s).
    ///
    /// Can be specified as:
    /// 1. A single string: -o "encrypted"
    /// 2. A comma-separated list: -o "enc1, enc2, enc3"
    /// 3. Numbered flags: -o1="enc1" -o2="enc2" -o3="enc3"
    #[arg(
        short = 'o',
        long = "output",
        required = false,
        value_delimiter = ',',
        value_parser = parse_numbered_or_list,
        num_args = 1..,
    )]
    output: Vec<String>,

    /// Name(s) for encrypted keys.
    ///
    /// Can be specified as:
    /// 1. A single string: -n "name"
    /// 2. A comma-separated list: -n "name1, name2, name3"
    /// 3. Numbered flags: -n1="name1" -n2="name2" -n3="name3"
    #[arg(
        short = 'n',
        long = "name",
        required = false,
        value_delimiter = ',',
        value_parser = parse_numbered_or_list,
        num_args = 1..,
    )]
    name: Vec<String>,

    /// (Optional) skip the prompt for a key name and auto-generate one instead. Only with -e or
    /// --encrypt
    ///
    /// Ignored when used with -n or --name
    #[arg(short = 'a', long = "auto-name", required = false)]
    auto_name: bool,

    /// (Optional) when provided, will skip (y/n) prompts and automatically overwrite existing files
    #[arg(short = 'f', long = "force-overwrite", required = false)]
    force: bool,
}

fn parse_numbered_or_list(input: &str) -> Result<String, String> {
    // Check if this is a numbered flag by looking for number prefix
    let prefix_pattern = format!(
        "{}{}",
        input.chars().next().unwrap_or('_'), // First char
        input.chars().nth(1).unwrap_or('_')  // Second char
    );

    match prefix_pattern.as_str() {
        // Match patterns like p1=, n2=, o3= at start of input
        s if s.chars().next().unwrap().is_ascii_digit() && s.chars().nth(1).unwrap() == '=' => {
            Ok(input
                .split_once('=')
                .map(|(_, v)| v)
                .unwrap_or(input)
                .to_string())
        }
        // Otherwise treat as regular input (comma-separated list or single value)
        _ => Ok(input.to_string()),
    }
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
    /// Preview the order that files will be processed in, during encryption or decryption with a given folder
    Preview {
        /// Specify `enc` or `dec` to preview file order for encryption or decryption with a given folder
        #[arg(value_parser = clap::value_parser!(String))]
        mode: String,
        /// Path to the folder you want to preview
        #[arg(value_parser = clap::value_parser!(PathBuf))]
        folder: PathBuf,
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
            } else if let Err(e) = MetadataManager.remove_metadata(&key_name.unwrap()) {
                eprintln!("{}", e);
            }
            return Ok(());
        }
        Some(Commands::Preview { mode, folder }) => {
            if !folder.is_dir() {
                eprintln!("The specified path is not a directory.");
                std::process::exit(1);
            }
            match mode.as_str() {
                "enc" => FileUtils::preview_files(&folder, true)?,
                "dec" => FileUtils::preview_files(&folder, false)?,
                _ => {
                    eprintln!("Specify either 'enc' or 'dec' for the preview mode.");
                    println!("(Or try `qlock preview --help` for more info)");
                    std::process::exit(1);
                }
            }
            return Ok(());
        }
        None => {}
    }

    if let Some(action) = cli.action {
        match (action.encrypt, action.decrypt) {
            (true, false) => {
                if let Err(e) = Encryptor::new().encrypt_files(
                    action.files,
                    action.output,
                    action.name,
                    action.password,
                    action.auto_name,
                    action.force,
                ) {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
            (false, true) => {
                if !action.name.is_empty() {
                    eprintln!("-n or --name will be ignored, not needed during decryption");
                }
                if action.auto_name {
                    eprintln!("-a or --auto-name will be ignored, not needed during decryption");
                }

                if let Err(e) = Decryptor::new().decrypt_files(
                    action.files,
                    action.output,
                    action.password,
                    action.force,
                ) {
                    eprintln!("{}", e);
                    std::process::exit(1);
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
