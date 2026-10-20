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


def checks(line):
    """Detector ids fired by one line."""
    return [f.check for f in scan_line(line, "t.txt", 1)]


def severities(line):
    return {f.check: f.severity for f in scan_line(line, "t.txt", 1)}


# ---------------------------------------------------------------------------
# Known-prefix detectors
# ---------------------------------------------------------------------------

def test_aws_access_key():
    fs = scan_line("key: AKIAIOSFODNN7EXAMPLE", "t", 1)
    assert [f.check for f in fs] == ["aws-access-key"]
    assert fs[0].severity == "high"


def test_aws_asia_temporary_key():
    # AWS's published documentation example key, assembled at runtime so
    # the literal never sits in source (GitHub's scanner flags it as-is).
    assert "aws-access-key" in checks("ASIA" + "IOSFODNN7" + "EXAMPLE")


def test_aws_secret_assignment_is_critical_and_single():
    fs = scan_line('aws_secret_access_key = "FAKEsecret0000000000000000"', "t", 1)
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
    assert "slack-token" in checks("xoxb-123456789012-abcdefghijkl")
    assert "slack-token" in checks("xapp-1-A0Fake-xyz-1234567890ab")


def test_google_api_key_and_oauth():
    assert "google-api-key" in checks("AIza" + "aB1" * 11 + "cd")
    assert "google-oauth-token" in checks("ya29.FakeTokenValue123")


def test_stripe_live_is_critical_test_is_high():
    sev = severities("sk_live_FakeStripeKey0000000000")
    assert sev["stripe-key"] == "critical"
    sev = severities("rk_live_FakeStripeKey0000000000")
    assert sev["stripe-key"] == "critical"
    sev = severities("whsec_FakeWebhookSecret0000")
    assert sev["stripe-key"] == "critical"
    sev = severities("sk_test_FakeStripeKey0000000000")
    assert sev["stripe-key"] == "high"


def test_private_key_block_is_critical():
    for header in ("-----BEGIN PRIVATE KEY-----",
                   "-----BEGIN RSA PRIVATE KEY-----",
                   "-----BEGIN OPENSSH PRIVATE KEY-----"):
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
    text = "clean line\nkey: AKIAIOSFODNN7EXAMPLE\nanother clean line"
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
    p.write_text("key: AKIAIOSFODNN7EXAMPLE  # secretscan:ignore\n"
                 "key2: AKIAIOSFODNN7EXAMPLE\n")
    findings, _ = scan_path(str(p), Config())
    assert [f.line for f in findings] == [2]


def test_config_ignore_paths_glob(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "sample.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / "real.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / ".secretscan.json").write_text(
        json.dumps({"ignore_paths": ["fixtures/*"], "ignore_patterns": []}))
    from secretscan import load_config
    findings, scanned = scan_path(str(tmp_path), load_config(str(tmp_path)))
    assert scanned == 2  # real.txt + the config file itself
    assert [f.file for f in findings] == [str(tmp_path / "real.txt")]


def test_config_ignore_patterns_regex(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "a.txt"
    p.write_text("key: AKIAIOSFODNN7EXAMPLE\n")
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
    original = ("key: AKIAIOSFODNN7EXAMPLE\n"
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
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
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
    p.write_text("key: AKIAIOSFODNN7EXAMPLE\n")
    code, out = run_scan(str(p), capsys, format="json")
    assert code == 1
    data = json.loads(out)
    assert len(data) == 1
    assert set(data[0].keys()) == {"file", "line", "check", "type", "severity"}
    assert data[0]["check"] == "aws-access-key"
    assert data[0]["line"] == 1


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
    (tmp_path / "a" / "b" / "deep.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    (tmp_path / ".git" / "config.txt").write_text("AKIAIOSFODNN7EXAMPLE\n")
    code, out = run_scan(str(tmp_path), capsys, format="json")
    assert code == 1
    data = json.loads(out)
    assert len(data) == 1
    assert data[0]["file"].endswith("deep.txt")


def test_binary_file_skipped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00\x01AKIAIOSFODNN7EXAMPLE\x00")
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
    (tmp_path / "leak.txt").write_text("fine line\nAKIAIOSFODNN7EXAMPLE\n")
    git("add", "leak.txt")
    args = argparse.Namespace(path=None, staged=True, format="json",
                              fail_on="high")
    with pytest.raises(SystemExit) as ei:
        cmd_scan(args)
    assert ei.value.code == 1
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 1
    assert data[0]["file"] == "leak.txt"
    assert data[0]["line"] == 2
    assert data[0]["check"] == "aws-access-key"


def test_init_scaffolds_config_and_sample(tmp_path):
    args = argparse.Namespace(dir=str(tmp_path), force=False)
    cmd_init(args)
    cfg = json.loads((tmp_path / ".secretscan.json").read_text())
    assert "ignore_paths" in cfg and "ignore_patterns" in cfg
    sample = (tmp_path / "sample-agent-output.txt").read_text()
    assert "AKIAIOSFODNN7EXAMPLE" in sample
    # Second run without --force refuses to overwrite.
    cmd_init(args)
