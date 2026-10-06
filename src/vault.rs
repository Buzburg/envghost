use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const _VAULT_DIR: &str = ".envghost";
pub const VAULT_FILE: &str = ".envghost/vault.json";
pub const CREDENTIAL_SERVICE: &str = "envghost";

#[derive(Default, PartialEq, Serialize, Deserialize)]
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
        if self.path.try_exists()? {
            return Err(io::Error::other(
                "Legacy plaintext vault detected. Run `envghost vault migrate` before using it.",
            ));
        }
        self.load_secure()
    }

    pub fn save(&self, data: &VaultData) -> io::Result<()> {
        if self.path.try_exists()? {
            return Err(io::Error::other(
                "Migrate the legacy plaintext vault before saving.",
            ));
        }
        self.save_secure(data)
    }

    fn entry(&self) -> io::Result<keyring::Entry> {
        let root = self
            .path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid vault path"))?
            .canonicalize()?;
        let account = format!("{:x}", Sha256::digest(root.as_os_str().as_encoded_bytes()));
        keyring::Entry::new(CREDENTIAL_SERVICE, &account).map_err(store_error)
    }

    fn load_secure(&self) -> io::Result<VaultData> {
        match self.entry()?.get_secret() {
            Ok(content) => serde_json::from_slice(&content).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid secure vault data")
            }),
            Err(keyring::Error::NoEntry) => Ok(VaultData::default()),
            Err(error) => Err(store_error(error)),
        }
    }

    fn save_secure(&self, data: &VaultData) -> io::Result<()> {
        let content = serde_json::to_vec(data)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid vault data"))?;
        self.entry()?.set_secret(&content).map_err(store_error)
    }

    pub fn migrate(&self) -> io::Result<()> {
        if fs::symlink_metadata(&self.path)?.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Legacy vault must not be a symlink",
            ));
        }
        let legacy: VaultData = serde_json::from_slice(&fs::read(&self.path)?)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid legacy vault data"))?;
        let existing = self.load_secure()?;
        if !existing.secrets.is_empty() && existing != legacy {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Secure vault already contains different data; plaintext was preserved",
            ));
        }
        self.save_secure(&legacy)?;
        if self.load_secure()? != legacy {
            return Err(io::Error::other(
                "Secure vault verification failed; plaintext was preserved",
            ));
        }
        fs::remove_file(&self.path)
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

fn store_error(_: keyring::Error) -> io::Error {
    // Do not format backend errors: some variants contain the secret bytes.
    io::Error::other("OS credential store unavailable, locked, or unable to store this vault; no plaintext fallback")
}
