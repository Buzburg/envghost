use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const _VAULT_DIR: &str = ".envghost";
pub const VAULT_FILE: &str = ".envghost/vault.json";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VaultData {
    pub secrets: HashMap<String, String>,
}

pub struct Vault {
    pub path: PathBuf,
}

impl Vault {
    pub fn new(root: &Path) -> Self {
        Self {
            path: root.join(VAULT_FILE),
        }
    }

    pub fn load(&self) -> io::Result<VaultData> {
        if !self.path.exists() {
            return Ok(VaultData::default());
        }
        let content = fs::read_to_string(&self.path)?;
        let data: VaultData = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(data)
    }

    pub fn save(&self, data: &VaultData) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&self.path, content)
    }

    pub fn set(&self, key: &str, val: &str) -> io::Result<()> {
        let mut data = self.load()?;
        data.secrets.insert(key.to_string(), val.to_string());
        self.save(&data)
    }

    pub fn get(&self, key: &str) -> io::Result<Option<String>> {
        let data = self.load()?;
        Ok(data.secrets.get(key).cloned())
    }

    pub fn list_keys(&self) -> io::Result<Vec<String>> {
        let data = self.load()?;
        let mut keys: Vec<_> = data.secrets.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }
}
