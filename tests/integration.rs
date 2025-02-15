mod common;

#[cfg(test)]
mod tests {
    use crate::common::{
        assert_command_success,
        assert_file_contents,
        assert_file_exists,
        execute_qlock_command,
        setup_test_directory,
    };

    #[test]
    fn test_encrypt_and_decrypt_one_file() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(&[("test.txt", "Lorem ipsum and so forth...")], &[])?;

        let encrypt_args = &["-e", "test.txt", "-p", "sixteenCharsPlus1", "-af"];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "test.qlock");

        let decrypt_args = &["-d", "test.qlock", "-p", "sixteenCharsPlus1", "-f"];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "test.txt");
        assert_file_contents(&temp_dir, "test.txt", "Lorem ipsum and so forth...")?;

        Ok(())
    }

    #[test]
    fn test_encrypt_and_decrypt_dir() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(
            &[
                ("test/one.md", "Lorem ipsum and so forth..."),
                ("test/nested/one.md", "Lorem ipsum and so forth..."),
                ("test/nested/two.md", "Lorem ipsum and so forth..."),
            ],
            &["test", "test/nested"],
        )?;

        let encrypt_args = &["-e", "test", "-p", "sixteenCharsPlus1", "-af"];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "test/one.qlock");
        assert_file_exists(&temp_dir, "test/nested/one.qlock");
        assert_file_exists(&temp_dir, "test/nested/two.qlock");

        let decrypt_args = &["-d", "test", "-p", "sixteenCharsPlus1", "-f"];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "test/one.md");
        assert_file_exists(&temp_dir, "test/nested/one.md");
        assert_file_exists(&temp_dir, "test/nested/two.md");
        assert_file_contents(&temp_dir, "test/one.md", "Lorem ipsum and so forth...")?;
        assert_file_contents(
            &temp_dir,
            "test/nested/one.md",
            "Lorem ipsum and so forth...",
        )?;
        assert_file_contents(
            &temp_dir,
            "test/nested/two.md",
            "Lorem ipsum and so forth...",
        )?;

        Ok(())
    }

    #[test]
    fn test_encrypt_and_decrypt_dir_with_output() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(
            &[
                ("test/one.md", "Lorem ipsum and so forth..."),
                ("test/nested/one.md", "Lorem ipsum and so forth..."),
                ("test/nested/two.md", "Lorem ipsum and so forth..."),
            ],
            &["test", "test/nested"],
        )?;

        let encrypt_args = &[
            "-e", "test",
            "-p", "sixteenCharsPlus1",
            "-o", "output",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "qlock_metadata.json");
        assert_file_exists(&temp_dir, "output-0000.qlock");
        assert_file_exists(&temp_dir, "output-0001.qlock");
        assert_file_exists(&temp_dir, "output-0002.qlock");

        let decrypt_args = &[
            "-d", temp_dir.path().to_str().unwrap(),
            "-p", "sixteenCharsPlus1",
            "-o", "output.md",
            "-f",
        ];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "output-0000.md");
        assert_file_exists(&temp_dir, "output-0001.md");
        assert_file_exists(&temp_dir, "output-0002.md");

        Ok(())
    }
}
