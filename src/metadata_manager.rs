use std::{
    fs::{self, create_dir_all},
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use terminal_size::{Width, terminal_size};
use textwrap;

use crate::qlock_errors::QlockError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Metadata {
    pub name: String,
    pub hash: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce_a: Vec<u8>,
    pub nonce_b: Vec<u8>,
    pub salt_a: Vec<u8>,
    pub salt_b: Vec<u8>,
    pub input_filename: String,
    pub output_filename: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MetadataList {
    pub data: Vec<Metadata>,
}

pub struct MetadataManager;

impl MetadataManager {
    pub const METADATA_DIR: &'static str = ".qlock_metadata";

    /// Reads all metadata.json files from .qlock_metadata/ and returns a MetadataList containing all entries.
    pub fn read_all(&self) -> io::Result<MetadataList> {
        let mut data = Vec::new();
        let dir = Path::new(Self::METADATA_DIR);

        if dir.exists() {
            let mut entries: Vec<_> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
            entries.sort_by_key(|e| e.file_name());
            for entry in entries {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    let contents = fs::read_to_string(&path)?;
                    if let Ok(meta) = serde_json::from_str::<Metadata>(&contents) {
                        data.push(meta);
                    }
                }
            }
        }

        Ok(MetadataList { data })
    }

    /// Write a single metadata file to `.qlock_metadata/`.
    pub fn write_one(&self, metadata: &Metadata) -> io::Result<PathBuf> {
        let path = Path::new(&metadata.output_filename);
        let file_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");
        let short_hash = metadata
            .hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .take(7)
            .collect::<String>();

        create_dir_all(Self::METADATA_DIR)?;

        let file_name = format!("{file_stem}.{short_hash}.json");
        let file_path = Path::new(Self::METADATA_DIR).join(file_name);

        let serialized = serde_json::to_string_pretty(metadata)?;
        fs::write(&file_path, serialized)?;

        println!(
            "Saved metadata for encrypted key '{}' to: {}/{}",
            metadata.name,
            Self::METADATA_DIR,
            file_path.file_name().unwrap().to_string_lossy()
        );

        Ok(file_path)
    }

    /// Save all metadata entries in the given MetadataList to individual files in .qlock_metadata.
    /// Each entry will be saved using write_metadata, using the output_filename and hash.
    pub fn write_all(&self, metadata_list: &MetadataList) -> io::Result<()> {
        for entry in &metadata_list.data {
            self.write_one(entry)?;
        }
        Ok(())
    }

    /// Checks if a key name already exists in the metadata directory.
    pub fn key_name_exists(&self, name: &str) -> bool {
        if let Ok(metadata_list) = self.read_all() {
            metadata_list.data.iter().any(|d| d.name == name)
        } else {
            false
        }
    }

    /// Lists all metadata entries from the metadata directory.
    /// If `key_name` is provided, only lists entries matching that name.
    /// Otherwise, lists all entries.
    pub fn list(&self, key_name: Option<String>) {
        let dir = Path::new(Self::METADATA_DIR);
        if !dir.exists() {
            println!(
                "{}/ does not exist, try encrypting something first or make sure you're in the correct directory.",
                Self::METADATA_DIR
            );
            return;
        }

        let width = if let Some((Width(w), _)) = terminal_size() {
            w as usize
        } else {
            80
        };

        match self.read_all() {
            Ok(metadata_list) => {
                if metadata_list.data.is_empty() {
                    println!("No encrypted keys were found in {}.", Self::METADATA_DIR);
                    return;
                }
                let mut was_found = false;
                for (index, datum) in metadata_list.data.iter().enumerate() {
                    if let Some(ref name) = key_name {
                        if &datum.name == name {
                            was_found = true;
                            self.print_one_metadata(index, datum, width);
                        }
                    } else {
                        self.print_one_metadata(index, datum, width);
                    }
                }
                if key_name.is_some() && !was_found {
                    eprintln!(
                        "No encrypted key with name '{}' was found in {}.",
                        key_name.unwrap(),
                        Self::METADATA_DIR
                    );
                    std::process::exit(1);
                }
            }
            Err(e) => println!("Error reading metadata: {e}"),
        }
    }

    fn print_one_metadata(&self, index: usize, datum: &Metadata, width: usize) {
        println!("{}. name: {}", (index + 1), datum.name);
        println!(
            "{:indent$}input file: {}",
            "",
            datum.input_filename,
            indent = 2
        );
        println!(
            "{:indent$}output file: {}",
            "",
            datum.output_filename,
            indent = 2
        );
        pretty_print_vec("encrypted key: ", &datum.key, 2, width);
        pretty_print_vec("hash of encrypted file: ", &datum.hash, 2, width);
        println!();
    }

    /// Removes the metadata file (from the `.qlock_metadata` directory) by key name.
    pub fn remove(&self, name: &str) -> Result<bool, QlockError> {
        let metadata_list = self.read_all().map_err(QlockError::IoError)?;
        let maybe_entry = metadata_list.data.iter().find(|d| d.name == name);

        if let Some(entry) = maybe_entry {
            let path = Path::new(&entry.output_filename);
            let file_stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");
            let short_hash = entry
                .hash
                .iter()
                .map(|b| format!("{b:02x}"))
                .take(7)
                .collect::<String>();
            let file_name = format!("{file_stem}.{short_hash}.json");
            let file_path = Path::new(Self::METADATA_DIR).join(&file_name);

            println!("{}", file_path.display());

            println!(
                "You will no longer be able to decrypt {}",
                entry.output_filename
            );
            println!("Are you sure you want to PERMANENTLY DELETE all metadata for {name}? (y/n)");

            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .map_err(QlockError::IoError)?;

            if input.trim() != "y" {
                println!("Metadata for {name} is still saved");
                return Ok(false);
            }

            fs::remove_file(&file_path).map_err(QlockError::IoError)?;

            println!(
                "Removed metadata for {} from: {}/{}",
                name,
                Self::METADATA_DIR,
                file_path.file_name().unwrap().to_string_lossy()
            );

            Ok(true)
        } else {
            Err(QlockError::MetadataNotFound(name.to_string()))
        }
    }
}

fn pretty_print_vec(preceeding: &str, vec: &[u8], indent: usize, width: usize) {
    let formatted = format!("{preceeding}{vec:?}");

    let indented = textwrap::fill(&formatted, width / 2)
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if i == 0 {
                line.to_string()
            } else {
                format!("{:indent$}{}", "", line, indent = indent + 2)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    println!("{:indent$}{}", "", indented, indent = indent);
}
