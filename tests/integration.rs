mod common;

#[cfg(test)]
mod tests {
    use crate::common::{
        assert_command_success, assert_file_contents, assert_file_exists, execute_qlock_command,
        execute_qlock_command_with_stdin, setup_test_directory,
    };

    #[test]
    fn encrypt_decrypt_one_file() -> Result<(), Box<dyn std::error::Error>> {
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
    fn encrypt_decrypt_multiple_files() -> Result<(), Box<dyn std::error::Error>> {
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
    fn encrypt_decrypt_multiple_files_with_one_output() -> Result<(), Box<dyn std::error::Error>> {
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
    fn encrypt_decrypt_multiple_files_with_multiple_outputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(
            &[
                ("test/one.md", "File Contents 1"),
                ("test/nested/two.md", "File Contents 2"),
                ("test/nested/three.md", "File Contents 3"),
            ],
            &["test", "test/nested"],
        )?;

        let encrypt_args = &[
            "-e",
            "test/one.md",
            "test/nested/two.md",
            "test/nested/three.md",
            "-p1=sixteenCharsPlus1",
            "-p2=sixteenCharsPlus2",
            "-p3=sixteenCharsPlus3",
            "-o1=output1",
            "-o2=output2",
            "-o3=output3",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "output1.qlock");
        assert_file_exists(&temp_dir, "output2.qlock");
        assert_file_exists(&temp_dir, "output3.qlock");

        let decrypt_args = &[
            "-d",
            "output1.qlock",
            "output2.qlock",
            "output3.qlock",
            "-p1=sixteenCharsPlus1",
            "-p2=sixteenCharsPlus2",
            "-p3=sixteenCharsPlus3",
            "-o1=decrypted1",
            "-o2=decrypted2",
            "-o3=decrypted3",
            "-f",
        ];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "decrypted1.md");
        assert_file_exists(&temp_dir, "decrypted2.md");
        assert_file_exists(&temp_dir, "decrypted3.md");
        assert_file_contents(&temp_dir, "decrypted1.md", "File Contents 1")?;
        assert_file_contents(&temp_dir, "decrypted2.md", "File Contents 2")?;
        assert_file_contents(&temp_dir, "decrypted3.md", "File Contents 3")?;

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_directory() -> Result<(), Box<dyn std::error::Error>> {
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

    #[test]
    fn encrypt_decrypt_directory_with_multiple_outputs() -> Result<(), Box<dyn std::error::Error>> {
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
            "sixteenCharsPlus1, sixteenCharsPlus2",
            "-o",
            "dir/output1, dir/output2",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "dir/output1.qlock");
        assert_file_exists(&temp_dir, "dir/output2.qlock");

        let decrypt_args = &[
            "-d",
            "dir/",
            "-p",
            "sixteenCharsPlus1, sixteenCharsPlus2",
            "-o",
            "decrypted1, decrypted2",
            "-f",
        ];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "decrypted1.txt");
        assert_file_exists(&temp_dir, "decrypted2.txt");
        assert_file_contents(&temp_dir, "decrypted1.txt", "Content of file 1")?;
        assert_file_contents(&temp_dir, "decrypted2.txt", "Content of file 2")?;

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_with_commas_in_passwords() -> Result<(), Box<dyn std::error::Error>> {
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
            r#"sixteenChars\,With\,Commas1, sixteenChars\,With\,Commas2"#,
            "-o",
            "dir/output1, dir/output2",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "dir/output1.qlock");
        assert_file_exists(&temp_dir, "dir/output2.qlock");

        let decrypt_args = &[
            "-d",
            "dir/",
            "-p",
            r#"sixteenChars\,With\,Commas1, sixteenChars\,With\,Commas2"#,
            "-o",
            "decrypted1, decrypted2",
            "-f",
        ];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "decrypted1.txt");
        assert_file_exists(&temp_dir, "decrypted2.txt");
        assert_file_contents(&temp_dir, "decrypted1.txt", "Content of file 1")?;
        assert_file_contents(&temp_dir, "decrypted2.txt", "Content of file 2")?;

        std::fs::remove_file(temp_dir.path().join("dir/output1.qlock"))?;
        std::fs::remove_file(temp_dir.path().join("dir/output2.qlock"))?;
        std::fs::remove_file(temp_dir.path().join("qlock_metadata.json"))?;

        let encrypt_args_numbered = &[
            "-e",
            "dir/",
            "-p1=sixteenChars,With,Commas1",
            "-p2=sixteenChars,With,Commas2",
            "-o1=dir/output1",
            "-o2=dir/output2",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args_numbered)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "dir/output1.qlock");
        assert_file_exists(&temp_dir, "dir/output2.qlock");

        let decrypt_args_numbered = &[
            "-d",
            "dir/",
            "-p1=sixteenChars,With,Commas1",
            "-p2=sixteenChars,With,Commas2",
            "-o1=decrypted1",
            "-o2=decrypted2",
            "-f",
        ];
        let decrypt_output = execute_qlock_command(&temp_dir, decrypt_args_numbered)?;
        assert_command_success(&decrypt_output);
        assert!(String::from_utf8_lossy(&decrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "decrypted1.txt");
        assert_file_exists(&temp_dir, "decrypted2.txt");
        assert_file_contents(&temp_dir, "decrypted1.txt", "Content of file 1")?;
        assert_file_contents(&temp_dir, "decrypted2.txt", "Content of file 2")?;

        Ok(())
    }

    #[test]
    fn encrypt_with_invalid_password_format() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(&[("test.txt", "file contents")], &[])?;

        let encrypt_args = &["-e", "test.txt", "-p", "sixteencharsplus1", "-af"];
        let output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("Passwords should contain a mix of upper and lower case characters...")
        );

        let encrypt_args = &["-e", "test.txt", "-p", "Short1", "-af"];
        let output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("Password was too short, it should be at least 16 characters long...")
        );

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_with_all_numbered_flags() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(
            &[
                ("file1.txt", "content1"),
                ("file2.txt", "content2"),
                ("file3.txt", "content3"),
            ],
            &[],
        )?;

        let encrypt_args = &[
            "-e",
            "file1.txt",
            "file2.txt",
            "file3.txt",
            "-p1=sixteenCharsPlus1",
            "-p2=sixteenCharsPlus2",
            "-p3=sixteenCharsPlus3",
            "-o1=out1",
            "-o2=out2",
            "-o3=out3",
            "-n1=key1",
            "-n2=key2",
            "-n3=key3",
            "-f",
        ];
        let output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&output);

        assert_file_exists(&temp_dir, "out1.qlock");
        assert_file_exists(&temp_dir, "out2.qlock");
        assert_file_exists(&temp_dir, "out3.qlock");

        let ls_output = execute_qlock_command(&temp_dir, &["ls"])?;
        let stdout = String::from_utf8_lossy(&ls_output.stdout);
        assert!(stdout.contains("key1"));
        assert!(stdout.contains("key2"));
        assert!(stdout.contains("key3"));

        let decrypt_args = &[
            "-d",
            "out1.qlock",
            "out2.qlock",
            "out3.qlock",
            "-p1=sixteenCharsPlus1",
            "-p2=sixteenCharsPlus2",
            "-p3=sixteenCharsPlus3",
            "-o1=decrypted1",
            "-o2=decrypted2",
            "-o3=decrypted3",
            "-f",
        ];
        let output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&output);

        assert_file_exists(&temp_dir, "decrypted1.txt");
        assert_file_exists(&temp_dir, "decrypted2.txt");
        assert_file_exists(&temp_dir, "decrypted3.txt");
        assert_file_contents(&temp_dir, "decrypted1.txt", "content1")?;
        assert_file_contents(&temp_dir, "decrypted2.txt", "content2")?;
        assert_file_contents(&temp_dir, "decrypted3.txt", "content3")?;

        Ok(())
    }

    #[test]
    fn encrypt_decrypt_with_mixed_flag_styles() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir =
            setup_test_directory(&[("file1.txt", "content1"), ("file2.txt", "content2")], &[])?;

        let encrypt_args = &[
            "-e",
            "file1.txt",
            "file2.txt",
            "-p1=sixteenCharsPlus1",
            "-p2=sixteenCharsPlus2",
            "-o",
            "output1, output2",
            "-n",
            "key1, key2",
            "-f",
        ];
        let output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&output);

        assert_file_exists(&temp_dir, "output1.qlock");
        assert_file_exists(&temp_dir, "output2.qlock");

        let decrypt_args = &[
            "-d",
            "output1.qlock",
            "output2.qlock",
            "-p1=sixteenCharsPlus1",
            "-p2=sixteenCharsPlus2",
            "-o1=decrypted1",
            "-o2=decrypted2",
            "-f",
        ];
        let output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert_command_success(&output);

        assert_file_exists(&temp_dir, "decrypted1.txt");
        assert_file_exists(&temp_dir, "decrypted2.txt");
        assert_file_contents(&temp_dir, "decrypted1.txt", "content1")?;
        assert_file_contents(&temp_dir, "decrypted2.txt", "content2")?;

        Ok(())
    }

    #[test]
    fn decrypt_with_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(&[("test.txt", "test content")], &[])?;

        let encrypt_args = &["-e", "test.txt", "-p", "sixteenCharsPlus1", "-f"];
        execute_qlock_command(&temp_dir, encrypt_args)?;

        let decrypt_args = &["-d", "test.qlock", "-p", "wrongPassword1234!", "-f"];
        let output = execute_qlock_command(&temp_dir, decrypt_args)?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Decryption error"));

        Ok(())
    }

    #[test]
    fn ls_command_with_no_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(&[], &[])?;
        let ls_args = &["ls"];
        let ls_output = execute_qlock_command(&temp_dir, ls_args)?;
        assert_command_success(&ls_output);
        assert!(
            String::from_utf8_lossy(&ls_output.stdout)
                .contains("qlock_metadata.json does not exist")
        );

        Ok(())
    }

    #[test]
    fn ls_command_with_metadata() -> Result<(), Box<dyn std::error::Error>> {
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
            "sixteenCharsPlus1, sixteenCharsPlus2",
            "-o",
            "dir/output1, dir/output2",
            "-af",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "dir/output1.qlock");
        assert_file_exists(&temp_dir, "dir/output2.qlock");

        let ls_args = &["ls"];
        let ls_output = execute_qlock_command(&temp_dir, ls_args)?;
        assert_command_success(&ls_output);
        assert!(String::from_utf8_lossy(&ls_output.stdout).contains("1."));
        assert!(String::from_utf8_lossy(&ls_output.stdout).contains("2."));

        Ok(())
    }

    #[test]
    fn ls_command_with_key_name() -> Result<(), Box<dyn std::error::Error>> {
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
            "sixteenCharsPlus1, sixteenCharsPlus2",
            "-o",
            "dir/output1, dir/output2",
            "-n",
            "key1, key2",
            "-f",
        ];
        let encrypt_output = execute_qlock_command(&temp_dir, encrypt_args)?;
        assert_command_success(&encrypt_output);
        assert!(String::from_utf8_lossy(&encrypt_output.stdout).contains("data was written to"));
        assert_file_exists(&temp_dir, "dir/output1.qlock");
        assert_file_exists(&temp_dir, "dir/output2.qlock");

        let ls_args = &["ls", "key2"];
        let ls_output = execute_qlock_command(&temp_dir, ls_args)?;
        assert_command_success(&ls_output);
        assert!(String::from_utf8_lossy(&ls_output.stdout).contains("2. name: key2"));
        assert!(!String::from_utf8_lossy(&ls_output.stdout).contains("1. name: key1"));

        Ok(())
    }

    #[test]
    fn rm_command() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(&[("test.txt", "test content")], &[])?;

        let encrypt_args = &[
            "-e",
            "test.txt",
            "-p",
            "sixteenCharsPlus1",
            "-n",
            "test-key",
            "-f",
        ];
        execute_qlock_command(&temp_dir, encrypt_args)?;

        let ls_args = &["ls", "test-key"];
        let output = execute_qlock_command(&temp_dir, ls_args)?;
        assert_command_success(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains("test-key"));

        let rm_args = &["rm", "test-key"];
        let output = execute_qlock_command_with_stdin(&temp_dir, rm_args, "y\n")?;
        assert_command_success(&output);
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("Removed metadata for test-key from: ./qlock_metadata.json")
        );

        let ls_args = &["ls", "test-key"];
        let output = execute_qlock_command(&temp_dir, ls_args)?;
        assert_command_success(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("test-key"));

        Ok(())
    }

    #[test]
    fn preview_command() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = setup_test_directory(
            &[
                ("dir/a.txt", "content"),
                ("dir/b.txt", "content"),
                ("dir/nested/c.txt", "content"),
            ],
            &["dir", "dir/nested"],
        )?;

        let preview_enc_args = &["preview", "enc", "dir"];
        let output = execute_qlock_command(&temp_dir, preview_enc_args)?;
        assert_command_success(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("1. dir/a.txt"));
        assert!(stdout.contains("2. dir/b.txt"));
        assert!(stdout.contains("3. dir/nested/c.txt"));

        let encrypt_args = &[
            "-e",
            "dir/",
            "-p",
            "sixteenCharsPlus1, sixteenCharsPlus1, sixteenCharsPlus1",
            "-f",
        ];
        execute_qlock_command(&temp_dir, encrypt_args)?;

        let preview_dec_args = &["preview", "dec", "dir"];
        let output = execute_qlock_command(&temp_dir, preview_dec_args)?;
        assert_command_success(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("1. dir/a.qlock"));
        assert!(stdout.contains("2. dir/b.qlock"));
        assert!(stdout.contains("3. dir/nested/c.qlock"));

        Ok(())
    }
}
