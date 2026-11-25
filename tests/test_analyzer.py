from prguard.analyzer import analyze_diff_text, format_markdown


def test_detects_secret_and_sensitive_path() -> None:
    diff = """diff --git a/.env b/.env
+++ b/.env
+GITHUB_TOKEN=ghp_1234567890abcdefghijklmnop
diff --git a/src/app.py b/src/app.py
+++ b/src/app.py
+print("hello")
"""
    summary = analyze_diff_text(diff, require_tests=True)
    assert summary.has_high_risk is True
    assert summary.risk_level == "HIGH"
    categories = {f.category for f in summary.findings}
    assert "Environment File" in categories
    assert "Secret Leak" in categories
    assert "Missing Tests" in categories
    md = format_markdown(summary)
    assert "## PRGuard Risk Summary" in md
    assert "[HIGH]" in md


def test_clean_diff_with_tests_scores_low() -> None:
    diff = """diff --git a/src/math_utils.py b/src/math_utils.py
+++ b/src/math_utils.py
+def add(a: int, b: int) -> int:
+    return a + b
diff --git a/tests/test_math.py b/tests/test_math.py
+++ b/tests/test_math.py
+def test_add():
+    assert 1 + 1 == 2
"""
    summary = analyze_diff_text(diff, require_tests=True)
    assert summary.has_high_risk is False
    assert summary.risk_level == "LOW"
    assert summary.findings == []
