# PRGuard

Zero-dependency Git diff risk analyzer, secret-leak scanner, and automated PR review summary CLI.

## Features
- **Secret Leak Detection:** Scans added diff lines for GitHub PATs, AWS Access Keys, Stripe Live keys, private key headers, and hardcoded credential literals.
- **Sensitive Path Alerts:** Flags modifications to `.env*`, `.github/workflows/*`, SQL migrations, Dockerfiles, and auth/security modules.
- **Blast-Radius & Test Hygiene:** Warns on oversized PRs (`> 500` changed lines) and source edits without accompanying tests (`--require-tests`).
- **PR Comment Ready:** Outputs `--markdown` summaries for GitHub Actions PR comments and `--json` for CI pipelines.

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Scan staged changes before committing
prguard scan --staged --fail-on-high

# Scan a branch diff against origin/main and emit a Markdown PR summary
prguard scan --base origin/main --require-tests --markdown

# Scan a saved unified diff fixture
prguard scan --diff examples/sample.diff --json
```

## Tests

```bash
pip install -e ".[dev]"
pytest -v
```
