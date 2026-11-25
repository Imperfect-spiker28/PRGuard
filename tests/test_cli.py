import json
from pathlib import Path

from prguard.cli import main


def test_cli_scan_diff_file_fail_on_high(tmp_path: Path, capsys) -> None:
    diff_file = tmp_path / "pr.diff"
    diff_file.write_text(
        "+++ b/config.py\n+API_KEY = 'super_secret_token_value_12345'\n",
        encoding="utf-8",
    )
    code = main(["scan", "--diff", str(diff_file), "--fail-on-high", "--json"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["has_high_risk"] is True
    assert payload["risk_level"] == "HIGH"


def test_cli_scan_clean_diff_markdown(tmp_path: Path, capsys) -> None:
    diff_file = tmp_path / "clean.diff"
    diff_file.write_text("+++ b/README.md\n+Docs update\n", encoding="utf-8")
    code = main(["scan", "--diff", str(diff_file), "--markdown"])
    assert code == 0
    out = capsys.readouterr().out
    assert "## PRGuard Risk Summary" in out
    assert "`LOW`" in out
