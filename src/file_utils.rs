use std::fs;
use std::io::{self};
use std::path::Path;

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
    ) -> io::Result<()> {
        if path.exists() && !Self::prompt_for_overwrite(path, operation) {
            println!(
                "{} not modified\n\n{} data was not output.",
                path.display(),
                operation
            );
            println!("If this was a mistake, you would need to run the command again and use `y` to overwrite the file.");
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

    pub fn get_files_in_dir(path: &Path) -> io::Result<fs::ReadDir> {
        fs::read_dir(path).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}
