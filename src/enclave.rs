use colored::*;
use std::collections::HashMap;
use std::process::Command;

pub struct Enclave;

impl Enclave {
    /// Executes a child command with real secrets injected into child process env,
    /// while redacting any real secrets that the child process prints to stdout/stderr.
    pub fn run_with_secrets(
        cmd_args: &[String],
        secrets: &HashMap<String, String>,
    ) -> std::io::Result<i32> {
        if cmd_args.is_empty() {
            eprintln!("{}", "Error: No command specified.".red());
            return Ok(1);
        }

        let program = &cmd_args[0];
        let args = &cmd_args[1..];

        println!(
            "{}",
            format!("► [envghost enclave] Launching '{}' with {} injected secret(s)...", program, secrets.len())
                .cyan()
                .bold()
        );

        let mut cmd = Command::new(program);
        cmd.args(args);

        // Inject real secrets into child process environment
        for (k, v) in secrets {
            cmd.env(k, v);
        }

        let output = cmd.output()?;

        let mut stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
        let mut stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

        // Sanitize output: if child printed any real secret, redact it immediately
        for (_, secret_val) in secrets {
            if secret_val.len() > 5 {
                stdout_str = stdout_str.replace(secret_val, "[REDACTED_BY_ENVGHOST]");
                stderr_str = stderr_str.replace(secret_val, "[REDACTED_BY_ENVGHOST]");
            }
        }

        print!("{}", stdout_str);
        eprint!("{}", stderr_str);

        let exit_code = output.status.code().unwrap_or(-1);
        Ok(exit_code)
    }
}
