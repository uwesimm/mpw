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

#[test]
fn test_default_values() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("password for user testuser and site testsite"));
    Ok(())
}

#[test]
fn test_counter_option() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .arg("-c")
        .arg("5")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("password for user testuser and site testsite"));
    Ok(())
}

#[test]
fn test_different_templates_produce_different_output() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd1 = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd1.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .arg("-t")
        .arg("x")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output1 = cmd1.output()?;
    let stdout1 = String::from_utf8_lossy(&output1.stdout);

    let mut cmd2 = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd2.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .arg("-t")
        .arg("p")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output2 = cmd2.output()?;
    let stdout2 = String::from_utf8_lossy(&output2.stdout);

    // Extract passwords from output - split on "is " and strip trailing characters
    let pw1 = stdout1
        .split("is ")
        .last()
        .unwrap_or("")
        .trim()
        .trim_matches('"');
    let pw2 = stdout2
        .split("is ")
        .last()
        .unwrap_or("")
        .trim()
        .trim_matches('"');

    assert_ne!(
        pw1, pw2,
        "Different templates should produce different passwords"
    );
    assert_eq!(pw1.len(), 20); // x template
    assert_eq!(pw2.len(), 4); // p template
    Ok(())
}

#[test]
fn test_context_option() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .arg("-x")
        .arg("mycontext")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("password for user testuser and site testsite"));
    Ok(())
}

#[test]
fn test_usage_option() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .arg("-k")
        .arg("i")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output = cmd.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("password for user testuser and site testsite"));
    Ok(())
}

#[test]
fn test_invalid_usage_character() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .arg("-k")
        .arg("z")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    cmd.assert().failure().stderr(predicate::str::contains(
        "usage character 'z' not recognized",
    ));
    Ok(())
}

#[test]
fn test_deterministic_same_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd1 = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd1.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output1 = cmd1.output()?;
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let pw1 = stdout1
        .split("is ")
        .last()
        .unwrap_or("")
        .trim()
        .trim_matches('"');

    let mut cmd2 = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd2.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output2 = cmd2.output()?;
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let pw2 = stdout2
        .split("is ")
        .last()
        .unwrap_or("")
        .trim()
        .trim_matches('"');

    assert_eq!(pw1, pw2, "Same inputs should produce same password");
    Ok(())
}

#[test]
fn test_different_sites_produce_different_passwords() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd1 = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd1.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("site1")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output1 = cmd1.output()?;
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let pw1 = stdout1
        .split("is ")
        .last()
        .unwrap_or("")
        .trim()
        .trim_matches('"');

    let mut cmd2 = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd2.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("site2")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output2 = cmd2.output()?;
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let pw2 = stdout2
        .split("is ")
        .last()
        .unwrap_or("")
        .trim()
        .trim_matches('"');

    assert_ne!(pw1, pw2);
    Ok(())
}

#[test]
fn test_different_users_produce_different_passwords() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd1 = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd1.arg("-u")
        .arg("user1")
        .arg("-s")
        .arg("testsite")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output1 = cmd1.output()?;
    let stdout1 = String::from_utf8_lossy(&output1.stdout);
    let pw1 = stdout1
        .split("is ")
        .last()
        .unwrap_or("")
        .trim()
        .trim_matches('"');

    let mut cmd2 = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd2.arg("-u")
        .arg("user2")
        .arg("-s")
        .arg("testsite")
        .env("MPW_MASTER_PASSWORD", "testmaster");

    let output2 = cmd2.output()?;
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    let pw2 = stdout2
        .split("is ")
        .last()
        .unwrap_or("")
        .trim()
        .trim_matches('"');

    assert_ne!(pw1, pw2);
    Ok(())
}
#[test]
fn test_zero_count_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite")
        .arg("-c")
        .arg("0")
        .env("MPW_MASTER_PASSWORD", "testmaster");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("counter must be at least 1"));
    Ok(())
}

#[test]
fn test_password_flag_is_gone() -> Result<(), Box<dyn std::error::Error>> {
    // The master password must never be passed via argv (visible in `ps`).
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("-p")
        .arg("secret")
        .arg("-u")
        .arg("testuser")
        .arg("-s")
        .arg("testsite");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("unexpected argument"));
    Ok(())
}

#[test]
fn test_serve_non_loopback_without_tls_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("mpw"));
    cmd.arg("--serve")
        .arg("--bind")
        .arg("0.0.0.0")
        .arg("--port")
        .arg("18099");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("refusing to serve plaintext HTTP"));
    Ok(())
}
