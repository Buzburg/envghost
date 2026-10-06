use crate::honeytoken::HoneyGenerator;
use crate::scanner::SecretScanner;
use std::collections::HashMap;

pub struct Virtualizer<'a> {
    scanner: &'a SecretScanner,
}

impl<'a> Virtualizer<'a> {
    pub fn new(scanner: &'a SecretScanner) -> Self {
        Self { scanner }
    }

    /// Transforms an unmasked .env string into a safe, virtualized version with honey-tokens
    pub fn mask_env_content(&self, content: &str) -> (String, HashMap<String, String>) {
        let mut masked_lines = Vec::new();
        let mut secret_map = HashMap::new(); // environment variable name -> real value

        for line in content.lines() {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                masked_lines.push(line.to_string());
                continue;
            }

            if let Some((k, v)) = line.split_once('=') {
                let trimmed_k = k.trim();
                let trimmed_v = v.trim().trim_matches('"').trim_matches('\'');

                let upper_k = trimmed_k.to_uppercase();
                let is_secret = upper_k.contains("KEY")
                    || upper_k.contains("SECRET")
                    || upper_k.contains("TOKEN")
                    || upper_k.contains("PASSWORD")
                    || upper_k.contains("CREDENTIAL")
                    || upper_k.contains("DATABASE")
                    || upper_k.contains("URL")
                    || trimmed_v.starts_with("sk_")
                    || trimmed_v.starts_with("ghp_")
                    || trimmed_v.starts_with("AKIA")
                    || trimmed_v.starts_with("postgres://")
                    || trimmed_v.starts_with("mysql://");

                if is_secret && !trimmed_v.is_empty() {
                    let sec_type = self.scanner.classify_secret_type(trimmed_k, trimmed_v);
                    let honey = HoneyGenerator::generate(&sec_type, trimmed_k);

                    secret_map.insert(trimmed_k.to_string(), trimmed_v.to_string());
                    masked_lines.push(format!("{}=\"{}\"", trimmed_k, honey));
                } else {
                    masked_lines.push(line.to_string());
                }
            } else {
                masked_lines.push(line.to_string());
            }
        }

        (masked_lines.join("\n"), secret_map)
    }
}
