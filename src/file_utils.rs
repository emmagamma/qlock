use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::metadata_manager::Metadata;
use crate::qlock_errors::QlockError;

pub struct FileUtils;

impl FileUtils {
    pub fn filter_files_for_enc(files: &[PathBuf]) -> Vec<PathBuf> {
        files
            .iter()
            .filter(|f| {
                f.extension().is_none_or(|ext| ext != "qlock")
                    && !f.components().any(|c| c.as_os_str() == ".qlock_metadata")
            })
            .cloned()
            .collect()
    }

    pub fn filter_files_for_dec(files: &[PathBuf]) -> Vec<PathBuf> {
        files
            .iter()
            .filter(|f| {
                f.extension().is_some_and(|ext| ext == "qlock")
                    && !f.components().any(|c| c.as_os_str() == ".qlock_metadata")
            })
            .cloned()
            .collect()
    }

    pub fn enc_output_path(
        file_path: &Path,
        output_flags: &[String],
        file_index: usize,
        file_total: usize,
    ) -> PathBuf {
        let parent_dir = file_path.parent().unwrap().to_string_lossy().to_string();
        let stem = file_path.file_stem().unwrap().to_str().unwrap().to_string();

        match output_flags {
            // Single output with multiple files - add counter to all files
            outputs if outputs.len() == 1 && file_total > 1 => {
                PathBuf::from(format!("{}-{:04}.qlock", outputs[0].trim(), file_index))
            }
            // Multiple outputs specified - use corresponding output or fall back to original filename
            outputs if !outputs.is_empty() => {
                if let Some(output) = outputs.get(file_index) {
                    PathBuf::from(format!("{}.qlock", output.trim()))
                } else {
                    // More files than outputs - fall back to original filename
                    if parent_dir.trim().is_empty() {
                        PathBuf::from(format!("{stem}.qlock"))
                    } else {
                        PathBuf::from(format!("{parent_dir}/{stem}.qlock"))
                    }
                }
            }
            // No outputs specified - use original filename
            _ => {
                if parent_dir.trim().is_empty() {
                    PathBuf::from(format!("{stem}.qlock"))
                } else {
                    PathBuf::from(format!("{parent_dir}/{stem}.qlock"))
                }
            }
        }
    }

    pub fn dec_output_path(
        metadata: &Metadata,
        outputs: &[String],
        idx: usize,
        total_files: usize,
    ) -> PathBuf {
        let original_ext = std::path::Path::new(&metadata.input_filename)
            .extension()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("txt");

        match outputs {
            // Single output with multiple files - add counter and extension
            outputs if outputs.len() == 1 && total_files > 1 => {
                let base_name = &outputs[0].trim();
                if std::path::Path::new(base_name).extension().is_some() {
                    let stem = std::path::Path::new(base_name)
                        .file_stem()
                        .unwrap()
                        .to_str()
                        .unwrap();
                    let ext = std::path::Path::new(base_name)
                        .extension()
                        .unwrap()
                        .to_str()
                        .unwrap();
                    PathBuf::from(format!("{stem}-{idx:04}.{ext}"))
                } else {
                    PathBuf::from(format!("{base_name}-{idx:04}.{original_ext}"))
                }
            }
            // Multiple outputs specified - use corresponding output or fall back
            outputs if outputs.len() > 1 => {
                if let Some(output) = outputs.get(idx) {
                    let output = output.trim();
                    if std::path::Path::new(output).extension().is_some() {
                        PathBuf::from(output)
                    } else {
                        PathBuf::from(format!("{output}.{original_ext}"))
                    }
                } else {
                    PathBuf::from(&metadata.input_filename)
                }
            }
            // No output specified - use original filename
            _ => PathBuf::from(&metadata.input_filename),
        }
    }
    pub fn prompt_for_overwrite(path: &Path, operation: &str) -> bool {
        println!(
            "File '{}' already exists. Do you want to overwrite it with the {} contents? (y/n)",
            path.display(),
            operation.to_lowercase()
        );
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        input.trim() == "y"
    }

    pub fn write_with_confirmation(
        path: &Path,
        contents: &[u8],
        operation: &str,
        force: bool,
    ) -> io::Result<()> {
        if !force && path.exists() && !Self::prompt_for_overwrite(path, operation) {
            println!(
                "{} not modified\n\n{} data was not output.",
                path.display(),
                operation
            );
            println!(
                "If this was a mistake, you would need to run the command again and use `y` to overwrite the file.\n"
            );
            return Ok(());
        }
        fs::write(path, contents)?;
        println!(
            "{} data was written to {} successfully\n",
            operation,
            path.display()
        );
        Ok(())
    }

    pub fn collect_files(paths: &[PathBuf]) -> io::Result<Vec<PathBuf>> {
        let mut all_files = Vec::new();

        for path in paths {
            if path.is_file() {
                all_files.push(path.to_path_buf());
            }
        }

        for path in paths {
            if path.is_dir() {
                let mut dir_files: Vec<_> = WalkDir::new(path)
                    .follow_links(true)
                    .into_iter()
                    .filter_map(|e| {
                        if let Ok(entry) = e {
                            let p = entry.path();
                            if p.is_file() {
                                Some(p.to_path_buf())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect();
                dir_files.sort();
                all_files.extend(dir_files);
            }
        }

        Ok(all_files)
    }

    pub fn preview_files(folder: &Path, is_encrypt: bool) -> Result<(), QlockError> {
        let all_files = FileUtils::collect_files(&[folder.to_path_buf()])?;
        let filtered_files: Vec<_> = if is_encrypt {
            FileUtils::filter_files_for_enc(&all_files)
        } else {
            FileUtils::filter_files_for_dec(&all_files)
        };

        if filtered_files.is_empty() {
            println!(
                "No files found in {} for the specified mode.",
                folder.display()
            );
            return Ok(());
        }

        println!(
            "Previewing files for {}:",
            if is_encrypt {
                "encryption"
            } else {
                "decryption"
            }
        );

        for (index, file) in filtered_files.iter().enumerate() {
            println!("{}. {}", index + 1, file.display());
        }

        Ok(())
    }

    pub fn get_or_prompt_password(
        password_flag: Option<&str>,
        is_encrypt: bool,
    ) -> Result<String, QlockError> {
        if let Some(pf) = password_flag {
            if FileUtils::is_valid_pass(pf) {
                Ok(pf.to_string())
            } else {
                std::process::exit(1);
            }
        } else {
            let prompt = if is_encrypt {
                "Don't forget to backup your password!\n\nIf you forget your password, you will not be able to decrypt your files!\n\n(min 16 chars, mix of upper + lower case, at least 1 number or special character)\nCreate a new password: "
            } else {
                "Enter password: "
            };
            loop {
                let pass = rpassword::prompt_password(prompt).map_err(QlockError::IoError)?;
                if FileUtils::is_valid_pass(&pass) {
                    return Ok(pass);
                }
                if !is_encrypt {
                    // For decryption, don't loop forever on invalid pass
                    return Err(QlockError::KeyDerivationError(
                        "Invalid password".to_string(),
                    ));
                }
            }
        }
    }

    pub fn is_valid_pass(password: &str) -> bool {
        let has_number_or_punctuation = password
            .chars()
            .any(|c| c.is_ascii_punctuation() || c.is_numeric());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());

        if password.len() < 16 {
            eprintln!("Password was too short, it should be at least 16 characters long...");

            if !has_uppercase || !has_lowercase {
                eprintln!("It should also contain a mix of upper and lower case letters");

                if !has_number_or_punctuation {
                    eprintln!("and at least 1 number or special character");
                }
            } else if !has_number_or_punctuation {
                eprintln!("It should also contain at least 1 number or special character\n");
            }

            eprintln!("Let's try again");

            return false;
        }

        if !has_uppercase || !has_lowercase {
            eprintln!("Passwords should contain a mix of upper and lower case characters...\n");

            if !has_number_or_punctuation {
                eprintln!("It was also missing at least 1 number or special character\n");
            }

            eprintln!("Let's try again");

            return false;
        }

        if !has_number_or_punctuation {
            eprintln!(
                "Password was missing at least 1 number or special character...\n\nLet's try again"
            );
            return false;
        }

        true
    }
}
