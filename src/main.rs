mod enclave;
mod honeytoken;
mod scanner;
mod vault;
mod virtualizer;

use clap::{Parser, Subcommand};
use colored::*;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use enclave::Enclave;
use scanner::SecretScanner;
use vault::Vault;
use virtualizer::Virtualizer;

#[derive(Parser)]
#[command(name = "envghost")]
#[command(about = "Credential masking, OS-backed storage, and child-process output redaction.")]
#[command(version = "0.1.1")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mask a .env file, replacing real credentials with format-valid synthetic honey-tokens
    Mask {
        /// Path to target .env file
        #[arg(default_value = ".env")]
        input: PathBuf,

        /// Output path for masked file
        #[arg(short, long, default_value = ".env.ghost")]
        out: PathBuf,
    },

    /// Scan a file or directory for exposed secrets and credentials
    Scan {
        /// Path to inspect
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Run a trusted command with stored credentials and redact its captured output
    Run {
        /// The command and arguments to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Manage credentials in the operating-system credential store
    Vault {
        #[command(subcommand)]
        action: VaultActions,
    },
}

#[derive(Subcommand)]
enum VaultActions {
    /// Verify an OS-backed copy, then remove the legacy plaintext vault
    Migrate,
    /// Store a secret in the local vault
    Set { key: String, value: String },
    /// Retrieve a secret
    Get { key: String },
    /// List all keys in vault
    List,
}

fn main() {
    let cli = Cli::parse();
    let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let scanner = SecretScanner::new();
    let vault = Vault::new(&current_dir);

    match cli.command {
        Commands::Mask { input, out } => {
            if !input.exists() {
                eprintln!(
                    "{}",
                    format!("Error: Input file '{}' does not exist.", input.display()).red()
                );
                process::exit(1);
            }

            let content = match fs::read_to_string(&input) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{}", format!("Error reading input: {}", e).red());
                    process::exit(1);
                }
            };

            let virtualizer = Virtualizer::new(&scanner);
            let (masked, map) = virtualizer.mask_env_content(&content);

            // Persist all discovered values before replacing the agent-facing file.
            if !map.is_empty() {
                let saved = vault.load().and_then(|mut data| {
                    data.secrets.extend(map.clone());
                    vault.save(&data)
                });
                if let Err(error) = saved {
                    eprintln!("Error storing credentials: {}", error);
                    process::exit(1);
                }
            }

            if let Err(e) = fs::write(&out, &masked) {
                eprintln!("{}", format!("Error writing masked output: {}", e).red());
                process::exit(1);
            }

            println!(
                "{}",
                format!(
                    "✔ Successfully virtualized '{}' -> '{}' ({} secrets replaced with honey-tokens)",
                    input.display(),
                    out.display(),
                    map.len()
                )
                .green()
                .bold()
            );
        }

        Commands::Scan { path } => {
            println!(
                "{}",
                format!("Scanning '{}' for credentials...", path.display()).bold()
            );
            let content = if path.is_file() {
                fs::read_to_string(&path).unwrap_or_default()
            } else {
                let env_path = path.join(".env");
                if env_path.exists() {
                    fs::read_to_string(&env_path).unwrap_or_default()
                } else {
                    String::new()
                }
            };

            let findings = scanner.scan_text(&content);
            if findings.is_empty() {
                println!("{}", "✔ No unprotected secrets detected.".green().bold());
            } else {
                println!(
                    "{}",
                    format!("⚠ Found {} unmasked secret(s):", findings.len())
                        .yellow()
                        .bold()
                );
                for f in findings {
                    println!(
                        "  line {:<3} | [{}] {} = {}",
                        f.line_number,
                        f.pattern_name.cyan(),
                        f.key_name.bold(),
                        "••••••••".red()
                    );
                }
                println!("\nRun `envghost mask` to protect these credentials before launching an AI agent.");
            }
        }

        Commands::Run { command } => {
            let vault_data = match vault.load() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{}", format!("Error loading vault: {}", e).red());
                    process::exit(1);
                }
            };

            match Enclave::run_with_secrets(&command, &vault_data.secrets) {
                Ok(code) => process::exit(code),
                Err(e) => {
                    eprintln!("{}", format!("Command execution error: {}", e).red());
                    process::exit(1);
                }
            }
        }

        Commands::Vault { action } => match action {
            VaultActions::Migrate => {
                if let Err(error) = vault.migrate() {
                    eprintln!("Vault migration failed: {}", error);
                    process::exit(1);
                }
                println!("Vault migrated and legacy plaintext removed.");
            }
            VaultActions::Set { key, value } => {
                if let Err(e) = vault.set(&key, &value) {
                    eprintln!("{}", format!("Error saving to vault: {}", e).red());
                    process::exit(1);
                }
                println!(
                    "{}",
                    format!("✔ Key '{}' stored in secure vault.", key).green()
                );
            }
            VaultActions::Get { key } => match vault.get(&key) {
                Ok(Some(val)) => println!("{}: {}", key, val),
                Ok(None) => println!("{}", format!("Key '{}' not found in vault.", key).yellow()),
                Err(e) => {
                    eprintln!("{}", format!("Error: {}", e).red());
                    process::exit(1);
                }
            },
            VaultActions::List => match vault.list_keys() {
                Ok(keys) => {
                    println!("Vault contains {} key(s):", keys.len());
                    for k in keys {
                        println!(" - {}", k.cyan());
                    }
                }
                Err(e) => {
                    eprintln!("{}", format!("Error: {}", e).red());
                    process::exit(1);
                }
            },
        },
    }
}
