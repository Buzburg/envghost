use sha2::{Digest, Sha256};

pub enum SecretType {
    StripeLive,
    StripeTest,
    OpenAi,
    GitHubPat,
    AwsAccessKey,
    DatabaseUrl,
    GenericToken,
}

pub struct HoneyGenerator;

impl HoneyGenerator {
    /// Generates a deterministic, format-compliant synthetic token derived from the secret name/seed
    pub fn generate(secret_type: &SecretType, key_name: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key_name.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        let short_hash = &hash[..16];

        match secret_type {
            SecretType::StripeLive => format!("sk_live_honey_{}", short_hash),
            SecretType::StripeTest => format!("sk_test_honey_{}", short_hash),
            SecretType::OpenAi => format!("sk-honey_{}_{}", short_hash, &hash[16..32]),
            SecretType::GitHubPat => format!("ghp_honey{}", &hash[..32]),
            SecretType::AwsAccessKey => format!("AKIAHONEY{}", &short_hash[..11].to_uppercase()),
            SecretType::DatabaseUrl => {
                "postgres://honey_user:honey_pass@localhost:5432/honey_db".to_string()
            }
            SecretType::GenericToken => format!("ghost_token_{}", short_hash),
        }
    }
}
