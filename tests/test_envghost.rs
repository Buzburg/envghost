use envghost::{SecretScanner, Virtualizer, Vault};
use tempfile::tempdir;

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
    let vault = Vault::new(dir.path());

    vault.set("STRIPE_KEY", "sk_live_secret123").unwrap();
    let retrieved = vault.get("STRIPE_KEY").unwrap();
    assert_eq!(retrieved, Some("sk_live_secret123".to_string()));

    let keys = vault.list_keys().unwrap();
    assert_eq!(keys, vec!["STRIPE_KEY"]);
}
