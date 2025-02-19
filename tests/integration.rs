mod common;

#[cfg(test)]
mod tests {
    use crate::common::{
        assert_command_success, assert_file_contents, assert_file_exists, execute_qlock_command,
        setup_test_directory
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
    fn test_encrypt_and_decrypt_multiple_files() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(
            &[
                ("test/zero.md", "0000"),
                ("test/nested/one.md", "0001"),
                ("test/nested/two.md", "0002"),
            ],
            &["test", "test/nested"],
        )?;

        let encrypt_args = &[
            "-e",
            "test/zero.md",
            "test/nested/one.md",
            "test/nested/two.md",
            "-p",
            "sixteenCharsPlus1, sixteenCharsPlus1, sixteenCharsPlus1",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "test/zero.qlock");
        assert_file_exists(&temp_dir, "test/nested/one.qlock");
        assert_file_exists(&temp_dir, "test/nested/two.qlock");

        let decrypt_args = &[
            "-d",
            "test/zero.qlock",
            "test/nested/one.qlock",
            "test/nested/two.qlock",
            "-p",
            "sixteenCharsPlus1, sixteenCharsPlus1, sixteenCharsPlus1",
            "-f",
        ];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "test/zero.md");
        assert_file_exists(&temp_dir, "test/nested/one.md");
        assert_file_exists(&temp_dir, "test/nested/two.md");
        assert_file_contents(&temp_dir, "test/zero.md", "0000")?;
        assert_file_contents(&temp_dir, "test/nested/one.md", "0001")?;
        assert_file_contents(&temp_dir, "test/nested/two.md", "0002")?;

        Ok(())
    }

    #[test]
    fn test_encrypt_and_decrypt_multiple_files_with_one_output() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(
            &[
                ("test/zero.md", "0000"),
                ("test/nested/one.md", "0001"),
                ("test/nested/two.md", "0002"),
            ],
            &["test", "test/nested"],
        )?;

        let encrypt_args = &[
            "-e",
            "test/zero.md",
            "test/nested/one.md",
            "test/nested/two.md",
            "-p",
            "sixteenCharsPlus1, sixteenCharsPlus1, sixteenCharsPlus1",
            "-o",
            "output",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        println!("{:?}", String::from_utf8_lossy(&encrypt_output.stdout));
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "output-0000.qlock");
        assert_file_exists(&temp_dir, "output-0001.qlock");
        assert_file_exists(&temp_dir, "output-0002.qlock");

        let decrypt_args = &[
            "-d",
            "output-0000.qlock",
            "output-0001.qlock",
            "output-0002.qlock",
            "-p",
            "sixteenCharsPlus1, sixteenCharsPlus1, sixteenCharsPlus1",
            "-o",
            "decrypted",
            "-f",
        ];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "decrypted-0000.md");
        assert_file_exists(&temp_dir, "decrypted-0001.md");
        assert_file_exists(&temp_dir, "decrypted-0002.md");
        assert_file_contents(&temp_dir, "decrypted-0000.md", "0000")?;
        assert_file_contents(&temp_dir, "decrypted-0001.md", "0001")?;
        assert_file_contents(&temp_dir, "decrypted-0002.md", "0002")?;

        Ok(())
    }

    #[test]
    fn test_encrypt_and_decrypt_directory() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(
            &[
                ("dir/file1.txt", "Content of file 1"),
                ("dir/file2.txt", "Content of file 2"),
            ],
            &["dir"],
        )?;

        let encrypt_args = &[
            "-e",
            "dir/",
            "-p",
            "sixteenCharsPlus1, sixteenCharsPlus1",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert_file_exists(&temp_dir, "dir/file1.qlock");
        assert_file_exists(&temp_dir, "dir/file2.qlock");

        let decrypt_args = &[
            "-d",
            "dir/",
            "-p",
            "sixteenCharsPlus1, sixteenCharsPlus1",
            "-f",
        ];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert_file_exists(&temp_dir, "dir/file1.txt");
        assert_file_exists(&temp_dir, "dir/file2.txt");
        assert_file_contents(&temp_dir, "dir/file1.txt", "Content of file 1")?;
        assert_file_contents(&temp_dir, "dir/file2.txt", "Content of file 2")?;

        Ok(())
    }
}
