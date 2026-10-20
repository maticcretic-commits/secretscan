"""Tests for SecretScan detectors, allowlist, redaction, and CLI."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from secretscan import (Config, cmd_init, cmd_redact, cmd_scan, luhn_valid,
                        scan_line, scan_path, shannon_entropy)

# Secret-shaped fixtures are assembled at runtime from fragments so no
# literal secret ever sits in this file (CONVENTIONS.md fixture policy);
# the runtime values are byte-identical to the formats under test.
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"
AWS_SECRET_NAME = "aws_" + "secret_access_key"
PK_PLAIN = "-----BEGIN " + "PRIVATE KEY-----"
PK_RSA = "-----BEGIN RSA " + "PRIVATE KEY-----"
PK_OPENSSH = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
STRIPE_LIVE = "sk_" + "live_FakeStripeKey0000000000"
STRIPE_RK_LIVE = "rk_" + "live_FakeStripeKey0000000000"
STRIPE_WEBHOOK = "whsec_" + "FakeWebhookSecret0000"
STRIPE_TEST = "sk_" + "test_FakeStripeKey0000000000"
SLACK_BOT = "xoxb-" + "123456789012-abcdefghijkl"
SLACK_APP = "xapp-" + "1-A0Fake-xyz-1234567890ab"
GOOGLE_OAUTH = "ya29." + "FakeTokenValue123"


def checks(line):
    """Detector ids fired by one line."""
    return [f.check for f in scan_line(line, "t.txt", 1)]


def severities(line):
    return {f.check: f.severity for f in scan_line(line, "t.txt", 1)}


# ---------------------------------------------------------------------------
# Known-prefix detectors
# ---------------------------------------------------------------------------

def test_aws_access_key():
    fs = scan_line("key: " + AWS_KEY, "t", 1)
    assert [f.check for f in fs] == ["aws-access-key"]
    assert fs[0].severity == "high"


def test_aws_asia_temporary_key():
    # AWS's published documentation example key, assembled at runtime so
    # the literal never sits in source (GitHub's scanner flags it as-is).
    assert "aws-access-key" in checks("ASIA" + "IOSFODNN7" + "EXAMPLE")


def test_aws_secret_assignment_is_critical_and_single():
    fs = scan_line(AWS_SECRET_NAME + ' = "FAKEsecret0000000000000000"', "t", 1)
    assert [f.check for f in fs] == ["aws-secret-key"]
    assert fs[0].severity == "critical"


def test_github_classic_token():
    assert "github-token" in checks("ghp_" + "Fake" * 9)


def test_github_fine_grained_pat():
    assert "github-token" in checks("github_pat_" + "FakeToken_" * 3)


def test_openai_variants():
    assert "openai-key" in checks("sk-ant-" + "a1B2" * 6)
    assert "openai-key" in checks("sk-proj-" + "a1B2" * 6)
    assert "openai-key" in checks("sk-" + "a1B2" * 9)


def test_slack_tokens():
    assert "slack-token" in checks(SLACK_BOT)
    assert "slack-token" in checks(SLACK_APP)


def test_google_api_key_and_oauth():
    assert "google-api-key" in checks("AIza" + "aB1" * 11 + "cd")
    assert "google-oauth-token" in checks(GOOGLE_OAUTH)


def test_stripe_live_is_critical_test_is_high():
    sev = severities(STRIPE_LIVE)
    assert sev["stripe-key"] == "critical"
    sev = severities(STRIPE_RK_LIVE)
    assert sev["stripe-key"] == "critical"
    sev = severities(STRIPE_WEBHOOK)
    assert sev["stripe-key"] == "critical"
    sev = severities(STRIPE_TEST)
    assert sev["stripe-key"] == "high"


def test_private_key_block_is_critical():
    for header in (PK_PLAIN, PK_RSA, PK_OPENSSH):
        fs = scan_line(header, "t", 1)
        assert [f.check for f in fs] == ["private-key"]
        assert fs[0].severity == "critical"


def test_jwt_is_medium():
    tok = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiJmYWtlLXVzZXIifQ.FakeSignatureValue000")
    fs = scan_line(tok, "t", 1)
    assert [f.check for f in fs] == ["jwt"]
    assert fs[0].severity == "medium"


# ---------------------------------------------------------------------------
# Generic assignments, PII, entropy
# ---------------------------------------------------------------------------

def test_generic_credential_assignment():
    fs = scan_line('db_password = "Sup3rSecret!"', "t", 1)
    assert [f.check for f in fs] == ["generic-credential"]
    assert fs[0].severity == "medium"


def test_generic_assignment_skips_references_and_placeholders():
    assert scan_line('api_key = os.environ["API_KEY"]', "t", 1) == []
    assert scan_line('token = "${API_TOKEN}"', "t", 1) == []
    assert scan_line('password = "changeme"', "t", 1) == []
    assert scan_line('api_key = "your-api-key"', "t", 1) == []


def test_generic_assignment_skips_plain_words():
    assert scan_line('auth = "production"', "t", 1) == []


def test_luhn_valid_and_invalid():
    assert luhn_valid("4242424242424242")
    assert luhn_valid("378282246310005")  # Amex test number
    assert not luhn_valid("4242424242424243")
    assert not luhn_valid("1234567890123")
    assert not luhn_valid("4242")          # too short
    assert not luhn_valid("not-a-number")


def test_credit_card_reported_only_when_luhn_valid():
    fs = scan_line("card: 4242 4242 4242 4242", "t", 1)
    assert [f.check for f in fs] == ["credit-card"]
    assert fs[0].severity == "high"
    assert scan_line("card: 4242 4242 4242 4243", "t", 1) == []


def test_ssn_is_medium():
    fs = scan_line("ssn: 123-45-6789", "t", 1)
    assert [f.check for f in fs] == ["ssn"]
    assert fs[0].severity == "medium"


def test_invalid_ssn_areas_not_reported():
    assert scan_line("ssn: 000-45-6789", "t", 1) == []
    assert scan_line("ssn: 666-45-6789", "t", 1) == []
    assert scan_line("ssn: 900-45-6789", "t", 1) == []


def test_phone_is_low():
    fs = scan_line("call 415-555-0132 today", "t", 1)
    assert [f.check for f in fs] == ["phone"]
    assert fs[0].severity == "low"


def test_shannon_entropy_values():
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") == 0.0
    assert shannon_entropy("abababababababababab") == 1.0
    assert shannon_entropy("Xk9mQ2wZ8vLpR4tY7nB3sD6fG1hJ5kM0") >= 4.5


def test_high_entropy_candidate_is_low():
    fs = scan_line("blob: Xk9mQ2wZ8vLpR4tY7nB3sD6fG1hJ5kM0", "t", 1)
    assert [f.check for f in fs] == ["high-entropy"]
    assert fs[0].severity == "low"


def test_entropy_ignores_words_and_short_strings():
    assert scan_line("the quick brown fox jumps over the lazy dog", "t", 1) == []
    assert scan_line("id: abc123", "t", 1) == []


def test_entropy_does_not_double_report_known_token():
    # The GitHub token is itself high-entropy; it must report once.
    assert checks("ghp_" + "Fake" * 9) == ["github-token"]


def test_line_numbers_are_per_line():
    text = "clean line\nkey: " + AWS_KEY + "\nanother clean line"
    findings, _ = scan_path_text(text)
    assert [(f.line, f.check) for f in findings] == [(2, "aws-access-key")]


def scan_path_text(text, name="trace.jsonl"):
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / name
        p.write_text(text, encoding="utf-8")
        return scan_path(str(p), Config())


# ---------------------------------------------------------------------------
# Allowlist: inline marker + config
# ---------------------------------------------------------------------------

def test_inline_ignore_marker_suppresses_line(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "a.txt"
    p.write_text("key: " + AWS_KEY + "  # secretscan:ignore\n"
                 "key2: " + AWS_KEY + "\n")
    findings, _ = scan_path(str(p), Config())
    assert [f.line for f in findings] == [2]


def test_config_ignore_paths_glob(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "sample.txt").write_text(AWS_KEY + "\n")
    (tmp_path / "real.txt").write_text(AWS_KEY + "\n")
    (tmp_path / ".secretscan.json").write_text(
        json.dumps({"ignore_paths": ["fixtures/*"], "ignore_patterns": []}))
    from secretscan import load_config
    findings, scanned = scan_path(str(tmp_path), load_config(str(tmp_path)))
    assert scanned == 2  # real.txt + the config file itself
    assert [f.file for f in findings] == [str(tmp_path / "real.txt")]


def test_config_ignore_patterns_regex(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "a.txt"
    p.write_text("key: " + AWS_KEY + "\n")
    (tmp_path / ".secretscan.json").write_text(
        json.dumps({"ignore_paths": [], "ignore_patterns": ["AKIA"]}))
    from secretscan import load_config
    findings, _ = scan_path(str(p), load_config(str(p)))
    assert findings == []


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def test_redact_replaces_and_preserves_original(tmp_path):
    src = tmp_path / "trace.txt"
    original = ("key: " + AWS_KEY + "\n"
                "card: 4242 4242 4242 4242\n"
                "nothing to hide\n")
    src.write_text(original)
    out = tmp_path / "cleaned"
    args = argparse.Namespace(path=str(src), out=str(out))
    with pytest.raises(SystemExit) as ei:
        cmd_redact(args)
    assert ei.value.code == 0
    # Original untouched.
    assert src.read_text() == original
    redacted = (out / "trace.txt").read_text()
    assert AWS_KEY not in redacted
    assert "4242 4242 4242 4242" not in redacted
    assert "[REDACTED:aws-access-key]" in redacted
    assert "[REDACTED:credit-card]" in redacted
    assert "nothing to hide" in redacted


def test_redact_directory_recursion(tmp_path):
    src = tmp_path / "run"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "a.txt").write_text("ghp_" + "Fake" * 9 + "\n")
    out = tmp_path / "out"
    args = argparse.Namespace(path=str(src), out=str(out))
    with pytest.raises(SystemExit) as ei:
        cmd_redact(args)
    assert ei.value.code == 0
    assert "[REDACTED:github-token]" in (out / "sub" / "a.txt").read_text()


# ---------------------------------------------------------------------------
# CLI: JSON shape, exit codes, directory recursion, edge cases
# ---------------------------------------------------------------------------

def run_scan(path, capsys, **kw):
    args = argparse.Namespace(path=path, staged=False,
                              format=kw.get("format", "text"),
                              fail_on=kw.get("fail_on", "high"))
    with pytest.raises(SystemExit) as ei:
        cmd_scan(args)
    return ei.value.code, capsys.readouterr().out


def test_json_output_shape(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "a.txt"
    p.write_text("key: " + AWS_KEY + "\n")
    code, out = run_scan(str(p), capsys, format="json")
    assert code == 1
    data = json.loads(out)
    findings = data["findings"]
    assert len(findings) == 1
    assert set(findings[0].keys()) == {"file", "line", "check", "type", "severity"}
    assert findings[0]["check"] == "aws-access-key"
    assert findings[0]["line"] == 1


def test_exit_code_zero_for_clean_file(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "clean.txt"
    p.write_text("just some agent notes, nothing sensitive\n")
    code, _ = run_scan(str(p), capsys)
    assert code == 0


def test_exit_code_respects_fail_on_threshold(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "a.txt"
    p.write_text("call 415-555-0132\n")  # low severity only
    code, _ = run_scan(str(p), capsys)                    # default: high
    assert code == 0
    code, _ = run_scan(str(p), capsys, fail_on="low")
    assert code == 1
    code, _ = run_scan(str(p), capsys, fail_on="critical")
    assert code == 0


def test_exit_code_two_for_missing_path(capsys):
    code, _ = run_scan("/definitely/not/here.txt", capsys)
    assert code == 2


def test_directory_recursion_and_git_skip(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    (tmp_path / "a" / "b" / "deep.txt").write_text(AWS_KEY + "\n")
    (tmp_path / ".git" / "config.txt").write_text(AWS_KEY + "\n")
    code, out = run_scan(str(tmp_path), capsys, format="json")
    assert code == 1
    data = json.loads(out)
    findings = data["findings"]
    assert len(findings) == 1
    assert findings[0]["file"].endswith("deep.txt")


def test_binary_file_skipped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x01" + AWS_KEY.encode() + b"\x00")
    findings, scanned = scan_path(str(p), Config())
    assert findings == [] and scanned == 0


def test_empty_file(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "empty.txt"
    p.write_text("")
    code, out = run_scan(str(p), capsys)
    assert code == 0
    assert "Clean" in out


def test_staged_scan_reports_json(tmp_path, monkeypatch, capsys):
    if subprocess.run(["git", "--version"], capture_output=True).returncode != 0:
        pytest.skip("git unavailable")
    monkeypatch.chdir(tmp_path)
    def git(*a):
        return subprocess.run(
            ["git", "-c", "user.email=t@t", "-c", "user.name=t", *a],
            capture_output=True, text=True, check=True)
    git("init", "-q")
    (tmp_path / "leak.txt").write_text("fine line\n" + AWS_KEY + "\n")
    git("add", "leak.txt")
    args = argparse.Namespace(path=None, staged=True, format="json",
                              fail_on="high")
    with pytest.raises(SystemExit) as ei:
        cmd_scan(args)
    assert ei.value.code == 1
    data = json.loads(capsys.readouterr().out)
    findings = data["findings"]
    assert len(findings) == 1
    assert findings[0]["file"] == "leak.txt"
    assert findings[0]["line"] == 2
    assert findings[0]["check"] == "aws-access-key"


def test_init_scaffolds_config_and_sample(tmp_path):
    args = argparse.Namespace(dir=str(tmp_path), force=False)
    cmd_init(args)
    cfg = json.loads((tmp_path / ".secretscan.json").read_text())
    assert "ignore_paths" in cfg and "ignore_patterns" in cfg
    sample = (tmp_path / "sample-agent-output.txt").read_text()
    assert AWS_KEY in sample
    # Second run without --force refuses to overwrite.
    cmd_init(args)


# ---------------------------------------------------------------------------
# Phase 1: JSON envelope, --version, error envelope, self-scan
# ---------------------------------------------------------------------------

CLI_PATH = Path(__file__).parent.parent / "src" / "secretscan.py"


def run_cli(*argv):
    return subprocess.run([sys.executable, str(CLI_PATH), *argv],
                          capture_output=True, text=True)


def test_json_envelope_and_summary(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "planted.txt"
    p.write_text(AWS_SECRET_NAME + ' = "FAKEsecret0000000000000000"\n'
                 "key: " + AWS_KEY + "\n")
    code, out = run_scan(str(p), capsys, format="json")
    assert code == 1
    data = json.loads(out)
    assert isinstance(data, dict)
    assert data["tool"] == "secretscan"
    assert data["version"] == "1.0.0"
    assert data["schema_version"] == 1
    # One critical (AWS secret assignment) + one high (AWS access key).
    assert data["findings_summary"] == {"count": 2,
                                        "highest_severity": "CRITICAL"}
    assert len(data["findings"]) == 2
    assert {f["check"] for f in data["findings"]} == {"aws-secret-key",
                                                      "aws-access-key"}
    # High-only file: highest_severity is HIGH.
    p2 = tmp_path / "highonly.txt"
    p2.write_text("key: " + AWS_KEY + "\n")
    code, out = run_scan(str(p2), capsys, format="json")
    assert code == 1
    data = json.loads(out)
    assert data["findings_summary"] == {"count": 1,
                                        "highest_severity": "HIGH"}
    # Clean file: count 0, highest_severity NONE.
    clean = tmp_path / "clean.txt"
    clean.write_text("just some agent notes, nothing sensitive\n")
    code, out = run_scan(str(clean), capsys, format="json")
    assert code == 0
    data = json.loads(out)
    assert data["findings_summary"] == {"count": 0,
                                        "highest_severity": "NONE"}
    assert data["findings"] == []


def test_version_flag():
    proc = run_cli("--version")
    assert proc.returncode == 0
    assert proc.stdout.strip() == "secretscan 1.0.0"


def test_missing_path_error_envelope():
    proc = run_cli("scan", "/definitely/not/here.txt")
    assert proc.returncode == 2
    lines = [ln for ln in proc.stderr.splitlines() if ln.strip()]
    assert lines[0] == "error: path not found: /definitely/not/here.txt"
    envelope = json.loads(lines[-1])
    assert envelope == {"error": {
        "code": "file_not_found",
        "message": "path not found: /definitely/not/here.txt"}}


def test_own_src_scans_clean():
    src = Path(__file__).parent.parent / "src"
    findings, scanned = scan_path(str(src), Config())
    assert scanned >= 1
    assert findings == []
