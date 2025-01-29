use std::{fs, io, path::Path};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedData {
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
        saved_data.data.push(additional_metadata);
        self.save_metadata(&saved_data)?;
        println!("saved key metadata to: ./{}", Self::METADATA_FILE);
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
