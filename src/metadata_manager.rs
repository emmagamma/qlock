use std::{fs, io, path::Path};

use serde::{Deserialize, Serialize};

use terminal_size::{terminal_size, Width};
use textwrap;

use crate::qlock_errors::QlockError;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedData {
    pub name: String,
    pub hash: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce_a: Vec<u8>,
    pub nonce_b: Vec<u8>,
    pub salt: Vec<u8>,
    pub hash_salt: Vec<u8>,
    pub filename: String,
    pub output_filename: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SavedData {
    pub data: Vec<EncryptedData>,
}

pub struct MetadataManager;

impl MetadataManager {
    pub const METADATA_FILE: &'static str = "qlock_metadata.json";

    pub fn write(&self, additional_metadata: EncryptedData) -> io::Result<()> {
        if !Path::new(Self::METADATA_FILE).exists() {
            let empty = SavedData { data: vec![] };
            self.save_metadata(&empty)?;
        }

        let mut saved_data = self.read()?;
        saved_data.data.push(additional_metadata.clone());
        self.save_metadata(&saved_data)?;
        println!(
            "saved metadata for {} to: ./{}",
            additional_metadata.name,
            Self::METADATA_FILE
        );
        Ok(())
    }

    pub fn read(&self) -> io::Result<SavedData> {
        if !Path::new(Self::METADATA_FILE).exists() {
            return Ok(SavedData { data: vec![] });
        }
        let metadata = fs::read_to_string(Self::METADATA_FILE)?;
        Ok(serde_json::from_str(&metadata)?)
    }

    pub fn save_metadata(&self, data: &SavedData) -> io::Result<()> {
        let serialized = serde_json::to_string(data)?;
        fs::write(Self::METADATA_FILE, serialized)
    }

    pub fn list(&self) {
        if !Path::new(Self::METADATA_FILE).exists() {
            println!("{} does not exist, try encrypting something first or make sure you're in the correct directory.", Self::METADATA_FILE);
            return;
        }

        let width = if let Some((Width(w), _)) = terminal_size() {
            w as usize
        } else {
            80
        };

        match self.read() {
            Ok(saved_data) => {
                if saved_data.data.is_empty() {
                    println!("No encrypted keys were found in {}.", Self::METADATA_FILE);
                    return;
                }
                for (index, datum) in saved_data.data.iter().enumerate() {
                    println!("{}. name: {}", (index + 1), datum.name);
                    println!("{:indent$}input file: {}", "", datum.filename, indent = 2);
                    println!(
                        "{:indent$}output file: {}",
                        "",
                        datum.output_filename,
                        indent = 2
                    );
                    pretty_print_vec("encrypted key: ", &datum.key, 2, width);
                    pretty_print_vec("hash of encrypted file: ", &datum.hash, 2, width);
                    println!("");
                }
            }
            Err(e) => println!("Error reading metadata: {}", e),
        }
    }

    pub fn remove_metadata(&self, name: &str) -> Result<bool, QlockError> {
        let mut saved_data = self.read().map_err(QlockError::IoError)?;
        let index = saved_data
            .data
            .iter()
            .position(|d| d.name == name)
            .ok_or(QlockError::MetadataNotFound(name.to_string()))?;

        println!(
            "are you sure you want to PERMANENTLY DELETE all metadata for {}? (y/n)",
            name
        );

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(QlockError::IoError)?;

        if input.trim() != "y" {
            println!("metadata for {} is still saved", name);
            return Ok(false);
        }

        saved_data.data.remove(index);

        self.save_metadata(&saved_data)
            .map_err(QlockError::IoError)?;

        println!(
            "removed metadata for {} from: ./{}",
            name,
            Self::METADATA_FILE
        );

        Ok(true)
    }
}

fn pretty_print_vec(preceeding: &str, vec: &[u8], indent: usize, width: usize) {
    let formatted = format!("{}{:?}", preceeding, vec); // Format the Vec<u8> using Debug trait

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
