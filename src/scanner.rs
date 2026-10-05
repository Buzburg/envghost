use regex::Regex;
use crate::honeytoken::SecretType;

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub key_name: String,
    #[allow(dead_code)]
    pub raw_value: String,
    pub line_number: usize,
    pub pattern_name: String,
}

pub struct SecretScanner {
    patterns: Vec<(&'static str, Regex)>,
}

impl SecretScanner {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                ("Stripe Live Key", Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap()),
                ("OpenAI API Key", Regex::new(r"sk-(proj-)?[a-zA-Z0-9_-]{32,}").unwrap()),
                ("GitHub PAT", Regex::new(r"ghp_[a-zA-Z0-9]{36}").unwrap()),
                ("AWS Access Key", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
                ("Database URI", Regex::new(r"postgres(ql)?://[^\s:]+:[^\s@]+@[^\s:]+:\d+/[^\s]+").unwrap()),
            ],
        }
    }

    pub fn scan_text(&self, text: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();

        for (line_idx, line) in text.lines().enumerate() {
            // Check key=value format (typical .env)
            if let Some((k, v)) = line.split_once('=') {
                let trimmed_k = k.trim();
                let trimmed_v = v.trim().trim_matches('"').trim_matches('\'');

                let upper_k = trimmed_k.to_uppercase();
                if (upper_k.contains("KEY") || upper_k.contains("SECRET") || upper_k.contains("TOKEN") || upper_k.contains("PASSWORD"))
                    && trimmed_v.len() > 6
                    && !trimmed_v.starts_with("ghost_")
                    && !trimmed_v.starts_with("honey_")
                {
                    findings.push(SecretFinding {
                        key_name: trimmed_k.to_string(),
                        raw_value: trimmed_v.to_string(),
                        line_number: line_idx + 1,
                        pattern_name: "Generic Secret / Key Env Var".to_string(),
                    });
                    continue;
                }
            }

            // Also check raw regex patterns
            for (name, re) in &self.patterns {
                for mat in re.find_iter(line) {
                    let val = mat.as_str();
                    if !val.contains("honey") {
                        findings.push(SecretFinding {
                            key_name: "INLINE_MATCH".to_string(),
                            raw_value: val.to_string(),
                            line_number: line_idx + 1,
                            pattern_name: name.to_string(),
                        });
                    }
                }
            }
        }

        findings
    }

    pub fn classify_secret_type(&self, key_name: &str, value: &str) -> SecretType {
        let upper = key_name.to_uppercase();
        if upper.contains("STRIPE") {
            if value.starts_with("sk_live") {
                SecretType::StripeLive
            } else {
                SecretType::StripeTest
            }
        } else if upper.contains("OPENAI") || value.starts_with("sk-") {
            SecretType::OpenAi
        } else if upper.contains("GITHUB") || value.starts_with("ghp_") {
            SecretType::GitHubPat
        } else if upper.contains("AWS") || value.starts_with("AKIA") {
            SecretType::AwsAccessKey
        } else if upper.contains("DATABASE") || value.contains("postgres://") {
            SecretType::DatabaseUrl
        } else {
            SecretType::GenericToken
        }
    }
}
