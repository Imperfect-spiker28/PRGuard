"""Unified diff parser, secret scanner, and PR blast-radius risk scorer."""

from dataclasses import dataclass, field
import re
from typing import Any

SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GitHub Personal Access Token", re.compile(r"(ghp_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,})")),
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe Live Secret Key", re.compile(r"sk_live_[0-9A-Za-z]{16,}")),
    ("Private Key Header", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    (
        "Hardcoded Secret Assignment",
        re.compile(r"""(?i)(api_key|secret_key|password|auth_token)\s*[:=]\s*["'][A-Za-z0-9_\-./+=]{12,}["']"""),
    ),
)

SENSITIVE_PATH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Environment File", re.compile(r"(^|/)\.env(\.|$)")),
    ("CI/CD Workflow", re.compile(r"^\.github/workflows/")),
    ("Database Migration", re.compile(r"(^|/)migrations/.*\.sql$")),
    ("Auth / Security Module", re.compile(r"(^|/)(auth|security|rbac|permissions?)[/_.]", re.I)),
    ("Container Build", re.compile(r"(^|/)Dockerfile")),
)


@dataclass
class Finding:
    severity: str  # "HIGH", "MEDIUM", "LOW"
    category: str
    file: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "message": self.message,
        }


@dataclass
class DiffSummary:
    files_changed: list[str] = field(default_factory=list)
    additions: int = 0
    deletions: int = 0
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "LOW"

    @property
    def has_high_risk(self) -> bool:
        return any(f.severity == "HIGH" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_changed": self.files_changed,
            "file_count": len(self.files_changed),
            "additions": self.additions,
            "deletions": self.deletions,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "has_high_risk": self.has_high_risk,
            "findings": [f.to_dict() for f in self.findings],
        }


def analyze_diff_text(diff_text: str, require_tests: bool = False) -> DiffSummary:
    """Parse a unified git diff and evaluate security, sensitive-path, and blast-radius risks."""
    summary = DiffSummary()
    current_file = "<unknown>"
    has_source_change = False
    has_test_change = False

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            if current_file not in summary.files_changed:
                summary.files_changed.append(current_file)
            for label, pat in SENSITIVE_PATH_PATTERNS:
                if pat.search(current_file):
                    sev = "HIGH" if label == "Environment File" else "MEDIUM"
                    summary.findings.append(
                        Finding(
                            severity=sev,
                            category=label,
                            file=current_file,
                            message=f"Sensitive path modified ({label})",
                        )
                    )
            lower = current_file.lower()
            if "test" in lower or lower.startswith("tests/"):
                has_test_change = True
            elif lower.endswith((".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs")):
                has_source_change = True
            continue

        if line.startswith("+") and not line.startswith("+++"):
            summary.additions += 1
            added_content = line[1:]
            for rule_name, rule_pat in SECRET_RULES:
                if rule_pat.search(added_content):
                    summary.findings.append(
                        Finding(
                            severity="HIGH",
                            category="Secret Leak",
                            file=current_file,
                            message=f"Potential {rule_name} detected in added line",
                        )
                    )
        elif line.startswith("-") and not line.startswith("---"):
            summary.deletions += 1

    if summary.additions + summary.deletions > 500:
        summary.findings.append(
            Finding(
                severity="MEDIUM",
                category="Large PR",
                file="*",
                message=f"Large diff ({summary.additions + summary.deletions} lines changed); consider splitting",
            )
        )

    if require_tests and has_source_change and not has_test_change:
        summary.findings.append(
            Finding(
                severity="MEDIUM",
                category="Missing Tests",
                file="*",
                message="Source files modified without accompanying test changes",
            )
        )

    score = 0
    for f in summary.findings:
        score += 40 if f.severity == "HIGH" else 15 if f.severity == "MEDIUM" else 5
    summary.risk_score = min(100, score)
    summary.risk_level = "HIGH" if summary.has_high_risk or summary.risk_score >= 60 else "MEDIUM" if summary.risk_score >= 20 else "LOW"
    return summary


def format_markdown(summary: DiffSummary) -> str:
    """Render a clean Markdown PR summary suitable for GitHub PR comments."""
    lines = [
        "## PRGuard Risk Summary",
        "",
        f"- **Risk Level:** `{summary.risk_level}` (Score: `{summary.risk_score}/100`)",
        f"- **Files Changed:** `{len(summary.files_changed)}` (`+{summary.additions}` / `-{summary.deletions}`)",
        "",
    ]
    if not summary.findings:
        lines.append("No security or blast-radius findings detected.")
    else:
        lines.append("### Findings")
        for f in summary.findings:
            lines.append(f"- **[{f.severity}] {f.category}** (`{f.file}`): {f.message}")
    return "\n".join(lines)
