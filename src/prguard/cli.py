"""Command-line interface for PRGuard."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from . import __version__
from .analyzer import analyze_diff_text, format_markdown


def _read_git_diff(repo: Path, base: str | None, staged: bool) -> str:
    cmd = ["git", "-C", str(repo), "diff"]
    if staged:
        cmd.append("--staged")
    elif base:
        cmd.append(f"{base}..HEAD")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git diff failed")
    return proc.stdout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prguard",
        description="Analyze git diffs for secret leaks, sensitive paths, and PR blast radius.",
    )
    parser.add_argument("--version", action="version", version=f"prguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a git repo diff or unified .diff file")
    scan.add_argument("--repo", type=Path, default=Path.cwd(), help="Git repository path")
    scan.add_argument("--base", default=None, help="Base git ref (e.g. origin/main)")
    scan.add_argument("--staged", action="store_true", help="Inspect staged changes")
    scan.add_argument("--diff", type=Path, default=None, help="Read unified diff from file instead of git")
    scan.add_argument("--require-tests", action="store_true", help="Flag source changes without test updates")
    scan.add_argument("--fail-on-high", action="store_true", help="Exit 1 when HIGH severity findings exist")
    scan.add_argument("--json", action="store_true", help="Emit JSON output")
    scan.add_argument("--markdown", action="store_true", help="Emit Markdown PR comment")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            if args.diff is not None:
                diff_text = args.diff.read_text(encoding="utf-8")
            else:
                diff_text = _read_git_diff(args.repo, args.base, args.staged)
        except (OSError, RuntimeError) as exc:
            print(f"Error reading diff: {exc}", file=sys.stderr)
            return 1

        summary = analyze_diff_text(diff_text, require_tests=args.require_tests)
        if args.json:
            print(json.dumps(summary.to_dict(), indent=2))
        elif args.markdown:
            print(format_markdown(summary))
        else:
            print(f"PRGuard v{__version__} — Risk: {summary.risk_level} ({summary.risk_score}/100)")
            print(f"  Files: {len(summary.files_changed)} (+{summary.additions}/-{summary.deletions})")
            for f in summary.findings:
                print(f"  [{f.severity}] {f.category} ({f.file}): {f.message}")

        if args.fail_on_high and summary.has_high_risk:
            return 1
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
