use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

pub fn setup_test_directory(
    files: &[(&str, &str)],
    directories: &[&str],
) -> Result<TempDir, Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;

    for dir in directories {
        fs::create_dir(temp_dir.path().join(dir))?;
    }

    for (file_path, contents) in files {
        fs::write(temp_dir.path().join(file_path), contents)?;
    }

    Ok(temp_dir)
}

pub fn execute_qlock_command(
    temp_dir: &TempDir,
    args: &[&str],
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("qlock")?;
    cmd.current_dir(temp_dir.path());
    cmd.args(args);

    Ok(cmd.assert().get_output().to_owned())
}

pub fn assert_command_success(output: &std::process::Output) {
    assert!(output.status.success());
}

pub fn assert_file_exists(temp_dir: &TempDir, file_path: &str) {
    assert!(temp_dir.path().join(file_path).exists());
}

pub fn assert_file_contents(
    temp_dir: &TempDir,
    file_path: &str,
    expected_contents: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_contents = fs::read_to_string(temp_dir.path().join(file_path))?;
    assert_eq!(file_contents, expected_contents);

    Ok(())
}
