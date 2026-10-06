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
            format!(
                "► [envghost] Launching '{}' with {} injected secret(s)...",
                program,
                secrets.len()
            )
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
        stdout_str = redact(&stdout_str, secrets);
        stderr_str = redact(&stderr_str, secrets);

        print!("{}", stdout_str);
        eprint!("{}", stderr_str);

        let exit_code = output.status.code().unwrap_or(-1);
        Ok(exit_code)
    }
}

fn redact(text: &str, secrets: &HashMap<String, String>) -> String {
    let mut values: Vec<&str> = secrets
        .values()
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .collect();
    values.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    values.dedup();
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(value) = values.iter().find(|value| rest.starts_with(**value)) {
            output.push_str("[REDACTED_BY_ENVGHOST]");
            rest = &rest[value.len()..];
        } else {
            let ch = rest.chars().next().expect("nonempty input");
            output.push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_handles_short_overlapping_unicode_and_empty_values() {
        let secrets = HashMap::from([
            ("short".into(), "a".into()),
            ("long".into(), "abc".into()),
            ("unicode".into(), "秘密".into()),
            ("empty".into(), String::new()),
            ("marker".into(), "REDACTED".into()),
        ]);
        assert_eq!(
            redact("abc a 秘密!", &secrets),
            "[REDACTED_BY_ENVGHOST] [REDACTED_BY_ENVGHOST] [REDACTED_BY_ENVGHOST]!"
        );
    }
}
