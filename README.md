# envghost 👻

> **Zero-Knowledge Honey-Credential Virtualizer & Secret Enclave for AI Coding Agents**

[![CI](https://github.com/buzburgai-arch/envghost/actions/workflows/ci.yml/badge.svg)](https://github.com/buzburgai-arch/envghost/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20or%20Apache--2.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/badge/crates.io-v0.1.0-orange.svg)](https://crates.io/crates/envghost)

`envghost` solves the fundamental security conflict in autonomous coding agents: **how to let agents run integration test suites without exposing production credentials, Stripe API keys, and database passwords to LLM context prompts and remote logs.**

```
 REAL ENVIRONMENT                  AGENT CONTEXT WINDOW
 ┌───────────────────────────┐     ┌───────────────────────────┐
 │ STRIPE_KEY = sk_live_9921 │ ──► │ STRIPE_KEY = sk_test_mock │
 │ AWS_SECRET = wJalrXUtn... │ ──► │ AWS_SECRET = mock_aws_... │
 └───────────────────────────┘     └───────────────────────────┘
               ▲
               │ (Seamless JIT Injection only during subprocess run)
               │
 ┌───────────────────────────┐
 │ Subprocess: pytest / test │ ◄── Tests execute and pass with REAL keys
 └───────────────────────────┘
```

---

## ⚡ Features

- **Synthetic Honey-Tokens:** Generates format-compliant, realistic synthetic keys (`sk_live_honey_...`, `ghp_honey...`) that satisfy regex, SDK format checks, and AST parsers.
- **Context Virtualization:** When an agent inspects `.env` or reads workspace files, it sees only synthetic honey-tokens. Real credentials never enter prompt context.
- **Just-In-Time Enclave Runner:** Launches child processes (`pytest`, `npm test`, `cargo test`) with real decrypted credentials in isolated sub-process memory.
- **Stdout/Stderr Redaction:** Intercepts child process output streams to scrub accidental credential echoes before they return to the agent terminal.

---

## 🚀 Quickstart

### Installation

```bash
cargo install envghost
```

### Usage

```bash
# 1. Scan your project for exposed secrets
envghost scan

# 2. Virtualize your .env into a safe agent-facing copy (.env.ghost)
envghost mask .env --out .env.ghost

# 3. Safely execute test suites in isolated enclave with real credentials
envghost run -- cargo test
```

---

## 🛠 Commands

| Command | Description |
| :--- | :--- |
| `envghost mask <file>` | Converts real `.env` into virtualized `.env.ghost` with honey-tokens |
| `envghost scan [path]` | Scans directory/files for unprotected credentials |
| `envghost run -- <cmd>` | Executes child process with real credentials in isolated enclave |
| `envghost vault [set/get/list]` | Manages local encrypted credentials store |

---

## 🧪 Testing

```bash
cargo test
```

---

## 📄 License

Dual-licensed under [MIT](LICENSE) or [Apache-2.0](LICENSE).
