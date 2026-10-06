# envghost 👻

Credential masking, operating-system credential storage, and child-process output redaction.

[![CI](https://github.com/buzburgai-arch/envghost/actions/workflows/ci.yml/badge.svg)](https://github.com/buzburgai-arch/envghost/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20or%20Apache--2.0-blue.svg)](LICENSE)

`envghost mask` creates a copy of an environment file with detected credentials replaced by synthetic tokens. It saves the real values under their environment variable names in the OS credential store. `envghost run` supplies those values to a trusted command and redacts exact matches in its captured standard output and error, including short secrets.

## Installation

```bash
cargo install --path . --locked
```

Storage uses Windows Credential Manager, macOS Keychain, or Linux Secret Service through [keyring](https://docs.rs/keyring/latest/keyring/v1/index.html). Linux needs an unlocked Secret Service and a session D-Bus. An unavailable or locked store causes an error; there is no plaintext fallback.

## Usage

```bash
envghost scan
envghost mask .env --out .env.ghost
envghost run -- cargo test
envghost vault list
```

The original `.env` remains unchanged. Give an agent the masked copy only, and keep the original outside its accessible files. Masking uses heuristics; review the output for credentials it did not recognize. Masking must successfully store the credentials before replacing the output file.

| Command | Description |
| :--- | :--- |
| `envghost mask <file> [--out <file>]` | Create a masked environment file and save detected values |
| `envghost scan [path]` | Scan a file, or a directory's `.env`, for known credential patterns |
| `envghost run -- <cmd>` | Inject stored environment variables and redact captured output |
| `envghost vault set <key> <value>` | Store a credential; command arguments may enter shell history |
| `envghost vault get <key>` | Print a credential in plaintext; use only in a trusted terminal |
| `envghost vault list` | List stored variable names |
| `envghost vault migrate` | Verify an OS-backed copy before removing a legacy plaintext vault |

## Existing vaults

Older versions wrote `.envghost/vault.json` as plaintext. Normal vault operations refuse to use that file until you explicitly run `envghost vault migrate` from the same project directory. Migration preserves the old file if parsing, storage, verification, or conflict checks fail. Removing the file does not erase copies in backups or Git history; rotate any credentials that were exposed.

Migration preserves legacy keys exactly. Older masking versions stored synthetic tokens as keys rather than environment variable names. Re-run `mask` against a trusted original environment file after migration to restore the proper variable names.

Each vault is associated with the canonical project directory and current OS user. Moving the project or switching users does not automatically transfer its vault. The serialized vault must fit the credential store's size limits; oversized writes return an error.

## Security scope

The OS store keeps the vault's secret values out of project files. This is not a sandbox or a cryptographic enclave: code running as the same OS user may access the store, and a launched command receives real credentials. Run trusted commands only. Redaction covers exact text matches in captured output; encoded values, files, network requests, and other side effects are outside its scope. Output is buffered until the child exits.

## Testing

```bash
cargo test --locked
```

Integration tests use temporary project directories and synthetic OS credential entries, which they remove afterward. On headless Linux, start an isolated D-Bus session and unlock a test keyring first; the CI workflow demonstrates this setup.

## License

Dual-licensed under [MIT](LICENSE) or [Apache-2.0](LICENSE).
