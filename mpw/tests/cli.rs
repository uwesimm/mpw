use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn file_doesnt_exist() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));

    cmd.arg("foobar").arg("test/file/doesnt/exist");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument 'foobar'"));

    Ok(())
}

#[test]
fn test_version_flag() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::starts_with("masterpassword "));
    Ok(())
}

#[test]
fn test_help_output() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("template to use"));
    Ok(())
}

#[test]
fn test_invalid_template() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("-t")
        .arg("z")
        .arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .env("MPW_MASTER_PASSWORD", "testmaster");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("template 'z' not recognized"));
    Ok(())
}