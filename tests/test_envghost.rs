use envghost::{SecretScanner, Vault, Virtualizer};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

// Each test uses a unique workspace/account and removes only its own synthetic data.
struct CredentialCleanup(keyring::Entry);

impl CredentialCleanup {
    fn new(root: &std::path::Path) -> Self {
        let root = root.canonicalize().unwrap();
        let account = format!("{:x}", Sha256::digest(root.as_os_str().as_encoded_bytes()));
        Self(keyring::Entry::new("envghost", &account).unwrap())
    }
}

impl Drop for CredentialCleanup {
    fn drop(&mut self) {
        match self.0.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(_) => eprintln!("Could not clean up the test credential"),
        }
    }
}

#[test]
fn test_mask_env_content() {
    let scanner = SecretScanner::new();
    let virtualizer = Virtualizer::new(&scanner);

    let raw_env = r#"
PORT=3000
NODE_ENV=production
STRIPE_SECRET_KEY="sk_live_1234567890abcdef1234567890"
OPENAI_API_KEY="sk-proj-1234567890abcdef1234567890abcdef123456"
DATABASE_URL="postgres://realuser:supersecretpass@db.prod.internal:5432/main"
"#;

    let (masked, map) = virtualizer.mask_env_content(raw_env);

    // Ensure raw secrets are NEVER in masked output
    assert!(!masked.contains("sk_live_1234567890abcdef1234567890"));
    assert!(!masked.contains("supersecretpass"));
    assert!(!masked.contains("sk-proj-1234567890"));

    // Ensure synthetic tokens ARE in masked output
    assert!(masked.contains("sk_live_honey_"));
    assert!(masked.contains("postgres://honey_user:honey_pass@localhost:5432/honey_db"));

    // Ensure non-secret config remains untouched
    assert!(masked.contains("PORT=3000"));
    assert!(masked.contains("NODE_ENV=production"));

    // Ensure secret map recorded real values
    assert_eq!(map.len(), 3);
}

#[test]
fn test_scanner_detection() {
    let scanner = SecretScanner::new();
    let sample = "Here is my secret token: ghp_111122223333444455556666777788889999 for access.";

    let findings = scanner.scan_text(sample);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].pattern_name, "GitHub PAT");
}

#[test]
fn test_vault_persistence() {
    let dir = tempdir().unwrap();
    let _cleanup = CredentialCleanup::new(dir.path());
    let vault = Vault::new(dir.path());

    vault.set("STRIPE_KEY", "sk_live_secret123").unwrap();
    let retrieved = Vault::new(dir.path()).get("STRIPE_KEY").unwrap();
    assert_eq!(retrieved, Some("sk_live_secret123".to_string()));

    let keys = vault.list_keys().unwrap();
    assert_eq!(keys, vec!["STRIPE_KEY"]);
}

#[test]
fn test_vault_never_writes_plaintext_credentials() {
    let dir = tempdir().unwrap();
    let _cleanup = CredentialCleanup::new(dir.path());
    let vault = Vault::new(dir.path());
    vault.set("REVIEW_KEY", "synthetic-review-secret").unwrap();
    assert!(!dir.path().join(".envghost/vault.json").exists());
}

#[test]
fn test_short_secret_is_redacted_from_child_output() {
    use std::process::Command;
    let dir = tempdir().unwrap();
    let _cleanup = CredentialCleanup::new(dir.path());
    let vault = Vault::new(dir.path());
    vault.set("REVIEW_SHORT", "ab123").unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_envghost"));
    command.current_dir(dir.path()).args(["run", "--"]);
    #[cfg(windows)]
    command.args([
        "cmd",
        "/C",
        "echo %REVIEW_SHORT% & echo %REVIEW_SHORT% 1>&2",
    ]);
    #[cfg(not(windows))]
    command.args([
        "sh",
        "-c",
        "printf '%s\\n' \"$REVIEW_SHORT\"; printf '%s\\n' \"$REVIEW_SHORT\" >&2",
    ]);
    let output = command.output().unwrap();
    assert!(output.status.success());
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("ab123"));
        assert!(text.contains("[REDACTED_BY_ENVGHOST]"));
    }
}

#[test]
fn test_legacy_migration_verifies_secure_copy() {
    let dir = tempdir().unwrap();
    let _cleanup = CredentialCleanup::new(dir.path());
    let vault = Vault::new(dir.path());
    std::fs::create_dir(dir.path().join(".envghost")).unwrap();
    std::fs::write(
        &vault.path,
        r#"{"secrets":{"TEST_KEY":"synthetic-legacy"}}"#,
    )
    .unwrap();
    assert!(vault.load().is_err());
    assert!(vault.set("TEST_KEY", "replacement").is_err());
    vault.migrate().unwrap();
    assert!(!vault.path.exists());
    assert_eq!(
        Vault::new(dir.path()).get("TEST_KEY").unwrap().as_deref(),
        Some("synthetic-legacy")
    );
}

#[test]
fn test_masked_credentials_reach_the_child_under_the_original_names() {
    let dir = tempdir().unwrap();
    let _cleanup = CredentialCleanup::new(dir.path());
    std::fs::write(dir.path().join(".env"), "API_KEY=ab123").unwrap();
    let mask = std::process::Command::new(env!("CARGO_BIN_EXE_envghost"))
        .current_dir(dir.path())
        .arg("mask")
        .output()
        .unwrap();
    assert!(mask.status.success());
    let mut run = std::process::Command::new(env!("CARGO_BIN_EXE_envghost"));
    run.current_dir(dir.path()).args(["run", "--"]);
    #[cfg(windows)]
    run.args(["cmd", "/C", "echo %API_KEY%"]);
    #[cfg(not(windows))]
    run.args(["sh", "-c", "printf '%s' \"$API_KEY\""]);
    let output = run.output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(!text.contains("ab123"));
    assert!(text.contains("[REDACTED_BY_ENVGHOST]"));
}

#[test]
fn test_legacy_conflict_preserves_both_copies() {
    let dir = tempdir().unwrap();
    let _cleanup = CredentialCleanup::new(dir.path());
    let vault = Vault::new(dir.path());
    vault.set("TEST_KEY", "secure-original").unwrap();
    std::fs::create_dir(dir.path().join(".envghost")).unwrap();
    let legacy = r#"{"secrets":{"TEST_KEY":"legacy-original"}}"#;
    std::fs::write(&vault.path, legacy).unwrap();
    assert!(vault.migrate().is_err());
    assert_eq!(std::fs::read_to_string(&vault.path).unwrap(), legacy);
    std::fs::remove_file(&vault.path).unwrap();
    assert_eq!(
        vault.get("TEST_KEY").unwrap().as_deref(),
        Some("secure-original")
    );
}

#[test]
fn test_mask_preserves_environment_names_and_masks_short_secrets() {
    let scanner = SecretScanner::new();
    let virtualizer = Virtualizer::new(&scanner);
    let (masked, values) = virtualizer.mask_env_content("API_KEY=abc\nPORT=3000");
    assert!(!masked.contains("abc"));
    assert!(masked.contains("PORT=3000"));
    assert_eq!(values.get("API_KEY").map(String::as_str), Some("abc"));
}

#[test]
fn test_mask_fails_without_overwriting_output_when_vault_needs_migration() {
    let dir = tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".envghost")).unwrap();
    std::fs::write(dir.path().join(".envghost/vault.json"), "{}").unwrap();
    std::fs::write(dir.path().join(".env"), "API_KEY=synthetic-secret").unwrap();
    std::fs::write(dir.path().join(".env.ghost"), "original-output").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_envghost"))
        .current_dir(dir.path())
        .arg("mask")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join(".env.ghost")).unwrap(),
        "original-output"
    );
}
