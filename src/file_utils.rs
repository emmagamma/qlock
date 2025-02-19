use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct FileUtils;

impl FileUtils {
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
        if !force {
            if path.exists() && !Self::prompt_for_overwrite(path, operation) {
                println!(
                    "{} not modified\n\n{} data was not output.",
                    path.display(),
                    operation
                );
                println!("If this was a mistake, you would need to run the command again and use `y` to overwrite the file.\n");
                return Ok(());
            }
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
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().is_file())
                    .map(|e| e.path().to_path_buf())
                    .collect();
                dir_files.sort();
                all_files.extend(dir_files);
            }
        }

        Ok(all_files)
    }
}
