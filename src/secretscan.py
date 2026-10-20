#!/usr/bin/env python3
"""
SecretScan — "Catch leaked secrets in agent outputs before they ship."

AI agents paste things. API keys into logs, tokens into traces, test card
numbers into sample outputs, private keys into "temporary" debug files —
and then someone commits the whole folder. SecretScan scans agent
outputs and artifacts (files, directories, or git staged changes) for
leaked secrets and PII *before* they ship, and can write redacted copies
that are safe to share.

Offline and dependency-free: pattern detectors for known token formats,
a Luhn check for card numbers, Shannon-entropy candidates, and an
allowlist for the fakes you keep on purpose.

Usage:
    secretscan scan <path> [--format text|json] [--fail-on LEVEL]
    secretscan scan --staged [--format json]
    secretscan redact <path> [--out DIR]
    secretscan init
"""

import argparse
import fnmatch
import json
import math
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.0.0"

SEVERITIES = ("low", "medium", "high", "critical")
SEV_RANK = {name: i for i, name in enumerate(SEVERITIES)}
IGNORE_MARKER = "secretscan:ignore"
CONFIG_NAME = ".secretscan.json"
ENTROPY_THRESHOLD = 4.5
ENTROPY_MIN_LENGTH = 20


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    line: int
    check: str        # detector id, e.g. "aws-access-key"
    type: str         # human label, e.g. "AWS access key"
    severity: str     # one of SEVERITIES
    match: str = ""   # the matched text (for redaction + masked display)

    def public(self):
        """The JSON-report shape: exactly these five fields."""
        return {"file": self.file, "line": self.line, "check": self.check,
                "type": self.type, "severity": self.severity}


@dataclass
class Config:
    ignore_paths: list = field(default_factory=list)    # globs
    ignore_patterns: list = field(default_factory=list)  # regex strings


# ---------------------------------------------------------------------------
# Detectors — each entry: (check id, type label, severity, compiled regex)
# Order matters: earlier (more specific) detectors win span overlaps.
# ---------------------------------------------------------------------------

PATTERN_DETECTORS = [
    ("private-key", "PEM private key block", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("stripe-key", "Stripe live secret key", "critical",
     re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    ("stripe-key", "Stripe webhook secret", "critical",
     re.compile(r"\bwhsec_[A-Za-z0-9]{16,}\b")),
    ("stripe-key", "Stripe test secret key", "high",
     re.compile(r"\b(?:sk|rk)_test_[A-Za-z0-9]{16,}\b")),
    ("aws-secret-key", "AWS secret access key", "critical",
     re.compile(r"(?i)\baws_secret_access_key\b")),
    ("aws-access-key", "AWS access key", "high",
     re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("github-token", "GitHub token", "high",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b|\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("openai-key", "OpenAI-style API key", "high",
     re.compile(r"\bsk-(?:ant|proj)-[A-Za-z0-9\-_]{20,}\b|\bsk-[A-Za-z0-9]{32,}\b")),
    ("slack-token", "Slack token", "high",
     re.compile(r"\bxox[bpars]-[A-Za-z0-9\-]{10,}\b|\bxapp-[A-Za-z0-9\-]{10,}\b")),
    ("google-api-key", "Google API key", "high",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("google-oauth-token", "Google OAuth token", "high",
     re.compile(r"\bya29\.[0-9A-Za-z\-_]{10,}\b")),
    ("jwt", "JSON Web Token", "medium",
     re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("ssn", "US Social Security number", "medium",
     re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
]

GENERIC_CREDENTIAL_RE = re.compile(
    r"(?i)\b[\w-]*(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|auth)"
    r"[\w-]*\b\s*[:=]\s*[\"']?([^\s\"',;]{8,})")

CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
PHONE_RE = re.compile(
    r"(?:\+?1[\s.\-]?)?(?:\(\d{3}\)|\b\d{3})[\s.\-]\d{3}[\s.\-]\d{4}\b")
ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-+/=]{%d,}" % ENTROPY_MIN_LENGTH)

# Values that are references or placeholders, not secrets.
_PLACEHOLDER_HINTS = ("environ", "getenv", "process.env", "${", "{{", "<!--")
_PLACEHOLDER_WORDS = {"changeme", "change-me", "example", "placeholder",
                      "your-api-key", "your_api_key", "xxxxxxxx", "********",
                      "redacted", "none", "null", "true", "false"}


def looks_like_placeholder(value):
    v = value.lower()
    if v in _PLACEHOLDER_WORDS:
        return True
    if any(h in v for h in _PLACEHOLDER_HINTS):
        return True
    if value.startswith("<") or "[" in value or "(" in value:
        return True
    # A single repeated character ("xxxxxxxx") or pure punctuation.
    if len(set(value)) <= 2:
        return True
    return False


def looks_token_like(value):
    """A generic-assignment value counts as credential-like when it is
    long enough and mixes character classes (not a plain word)."""
    if len(value) < 8 or looks_like_placeholder(value):
        return False
    classes = sum([
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ])
    return classes >= 2


def shannon_entropy(text):
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def luhn_valid(digits):
    """True when a digit string passes the Luhn checksum."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(explicit_start=None):
    """Load .secretscan.json: search the explicit start (a dir, or a
    file's parent), then the current directory. First found wins;
    a missing or malformed config means 'no ignores', never a crash."""
    candidates = []
    if explicit_start is not None:
        p = Path(explicit_start)
        candidates.append(p if p.is_dir() else p.parent)
    candidates.append(Path.cwd())
    seen = set()
    for base in candidates:
        if base in seen:
            continue
        seen.add(base)
        cfg_path = base / CONFIG_NAME
        if cfg_path.is_file():
            try:
                data = json.loads(cfg_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return Config()
            if isinstance(data, dict):
                return Config(
                    ignore_paths=[str(x) for x in data.get("ignore_paths", [])],
                    ignore_patterns=[str(x) for x in data.get("ignore_patterns", [])],
                )
            return Config()
    return Config()


def path_ignored(path_str, config):
    name = Path(path_str).name
    for g in config.ignore_paths:
        if (fnmatch.fnmatch(path_str, g) or fnmatch.fnmatch(name, g)
                or fnmatch.fnmatch(path_str, "*/" + g)):
            return True
    return False


def _line_ignored(line, config, compiled_patterns):
    if IGNORE_MARKER in line:
        return True
    return any(rx.search(line) for rx in compiled_patterns)


def compile_ignore_patterns(config):
    out = []
    for pat in config.ignore_patterns:
        try:
            out.append(re.compile(pat))
        except re.error:
            continue  # a bad ignore regex ignores nothing, never crashes
    return out


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _overlaps(span, spans):
    return any(span[0] < s[1] and s[0] < span[1] for s in spans)


def scan_line(line, filename, lineno):
    """Run every detector over one line. Returns a list of Finding.
    Earlier detectors win span overlaps; the generic-assignment and
    entropy detectors are fallbacks that never double-report a line
    (or a span) a specific detector already claimed."""
    findings = []
    claimed = []  # (start, end) spans already reported on this line

    def add(check, label, severity, m):
        findings.append(Finding(filename, lineno, check, label, severity,
                                m.group(0)))
        claimed.append((m.start(), m.end()))

    for check, label, severity, rx in PATTERN_DETECTORS:
        for m in rx.finditer(line):
            if not _overlaps((m.start(), m.end()), claimed):
                add(check, label, severity, m)

    # Credit cards: candidates verified with Luhn before reporting.
    for m in CARD_CANDIDATE_RE.finditer(line):
        if _overlaps((m.start(), m.end()), claimed):
            continue
        digits = re.sub(r"[ -]", "", m.group(0))
        if luhn_valid(digits):
            add("credit-card", "Credit card number (Luhn-verified)", "high", m)

    # Generic credential assignment — only when no specific detector
    # fired on this line at all, so an AWS secret-key assignment
    # reports once, as the AWS finding.
    if not findings:
        for m in GENERIC_CREDENTIAL_RE.finditer(line):
            if looks_token_like(m.group(1)):
                findings.append(Finding(
                    filename, lineno, "generic-credential",
                    "Credential assignment", "medium", m.group(1)))
                claimed.append((m.start(1), m.end(1)))
                break

    # Phone numbers.
    for m in PHONE_RE.finditer(line):
        if not _overlaps((m.start(), m.end()), claimed):
            add("phone", "Phone number", "low", m)

    # High-entropy candidates — fallback only, never overlapping a span
    # a real detector claimed.
    for m in ENTROPY_TOKEN_RE.finditer(line):
        if _overlaps((m.start(), m.end()), claimed):
            continue
        token = m.group(0)
        if len(set(token)) <= 2:
            continue
        if shannon_entropy(token) >= ENTROPY_THRESHOLD:
            add("high-entropy", "High-entropy string", "low", m)

    return findings


def scan_lines(lines, filename, config, compiled_patterns):
    out = []
    for lineno, line in enumerate(lines, start=1):
        if _line_ignored(line, config, compiled_patterns):
            continue
        out.extend(scan_line(line, filename, lineno))
    return out


def is_binary_bytes(data):
    return b"\x00" in data[:8192]


def iter_files(root):
    """Yield scannable file paths under a file or directory path,
    skipping .git/ internals."""
    root = Path(root)
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_file() and ".git" not in p.parts:
            yield p


def scan_path(path, config):
    """Scan a file or directory. Returns (findings, files_scanned).
    Raises FileNotFoundError for a missing path."""
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"path not found: {path}")
    compiled = compile_ignore_patterns(config)
    findings, scanned = [], 0
    for f in iter_files(root):
        display = str(f)
        if path_ignored(display, config):
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if is_binary_bytes(data):
            continue
        scanned += 1
        text = data.decode("utf-8", errors="replace")
        findings.extend(scan_lines(text.splitlines(), display, config, compiled))
    return findings, scanned


def staged_changes():
    """Return [(filename, lineno, text)] for lines added in
    `git diff --cached`. Raises RuntimeError when git fails."""
    proc = subprocess.run(
        ["git", "diff", "--cached", "--no-color", "-U0"],
        capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            "git diff --cached failed (not a git repo?): "
            + proc.stderr.strip())
    entries = []
    filename, new_lineno = None, 0
    for raw in proc.stdout.splitlines():
        if raw.startswith("+++ b/"):
            filename = raw[6:]
        elif raw.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw)
            new_lineno = int(m.group(1)) if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            if filename is not None:
                entries.append((filename, new_lineno, raw[1:]))
            new_lineno += 1
        elif raw.startswith("\\"):
            continue
        else:
            # Context line (none with -U0) or removed line: only the
            # new-file counter moves on '+' and context lines.
            if not raw.startswith("-"):
                new_lineno += 1
    return entries


def scan_staged(config):
    compiled = compile_ignore_patterns(config)
    by_file = {}
    order = []
    for filename, lineno, text in staged_changes():
        if filename not in by_file:
            by_file[filename] = []
            order.append(filename)
        by_file[filename].append((lineno, text))
    findings, files = [], 0
    for filename in order:
        if path_ignored(filename, config):
            continue
        files += 1
        for lineno, text in by_file[filename]:
            if _line_ignored(text, config, compiled):
                continue
            findings.extend(scan_line(text, filename, lineno))
    return findings, files


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def redact_text(text, filename, config, compiled):
    """Return the text with every detected secret replaced by
    [REDACTED:<check>]. Lines carrying the ignore marker pass through."""
    out_lines = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _line_ignored(line, config, compiled):
            out_lines.append(line)
            continue
        findings = scan_line(line, filename, lineno)
        # Replace right-to-left so earlier spans stay valid.
        spans = []
        for f in findings:
            idx = line.find(f.match)
            while idx != -1 and any(idx < e and s < idx + len(f.match)
                                    for s, e in spans):
                idx = line.find(f.match, idx + 1)
            if idx != -1:
                spans.append((idx, idx + len(f.match), f.check))
        new_line = line
        for start, end, check in sorted(spans, reverse=True):
            new_line = new_line[:start] + f"[REDACTED:{check}]" + new_line[end:]
        out_lines.append(new_line)
    result = "\n".join(out_lines)
    if text.endswith("\n"):
        result += "\n"
    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}


def masked(match):
    if len(match) <= 10:
        return match
    return match[:10] + "…"


def verdict_for(findings, fail_on):
    threshold = SEV_RANK[fail_on]
    return any(SEV_RANK[f.severity] >= threshold for f in findings)


def print_text_report(findings, scanned, fail_on, source_label):
    print("=" * 68)
    print("SecretScan — scan report")
    print("=" * 68)
    print(f"Source:  {source_label}")
    print(f"Scanned: {scanned} file(s) · {len(findings)} finding(s)")
    print()
    if not findings:
        print("✅ Clean — no secrets or PII found.")
        return
    by_file = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    for fname, items in by_file.items():
        print(f"## {fname}")
        for f in sorted(items, key=lambda x: x.line):
            print(f"  line {f.line:<5} {SEV_ICON[f.severity]} "
                  f"{f.severity.upper():<8} [{f.check}] {f.type} — "
                  f"{masked(f.match)}")
        print()
    if verdict_for(findings, fail_on):
        n = sum(1 for f in findings if SEV_RANK[f.severity] >= SEV_RANK[fail_on])
        print(f"❌ FAIL — {n} finding(s) at or above '{fail_on}'")
    else:
        print(f"✅ PASS — no findings at or above '{fail_on}' "
              f"(findings below the threshold are listed above)")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def error_exit(code, message):
    """Caller error (exit 2): the human line plus one JSON error-envelope
    line, both to stderr (see CONVENTIONS.md)."""
    print(f"error: {message}", file=sys.stderr)
    print(json.dumps({"error": {"code": code, "message": message}}),
          file=sys.stderr)
    sys.exit(2)


def cmd_scan(args):
    if args.staged:
        config = load_config()
        try:
            findings, scanned = scan_staged(config)
        except RuntimeError as e:
            error_exit("staged_scan_failed", str(e))
        label = "git staged changes"
    else:
        if not args.path:
            error_exit("missing_path", "scan needs a path (or --staged)")
        config = load_config(args.path)
        if path_ignored(str(args.path), config) and Path(args.path).is_dir():
            findings, scanned = [], 0
        else:
            try:
                findings, scanned = scan_path(args.path, config)
            except FileNotFoundError as e:
                error_exit("file_not_found", str(e))
        label = str(args.path)
    if args.format == "json":
        if any(f.severity == "critical" for f in findings):
            highest = "CRITICAL"
        elif any(f.severity == "high" for f in findings):
            highest = "HIGH"
        elif findings:
            highest = "INFO"
        else:
            highest = "NONE"
        print(json.dumps({
            "tool": "secretscan",
            "version": VERSION,
            "schema_version": 1,
            "findings_summary": {"count": len(findings),
                                 "highest_severity": highest},
            "findings": [f.public() for f in findings],
        }, indent=2))
    else:
        print_text_report(findings, scanned, args.fail_on, label)
    # 0 = nothing at/above the fail-on threshold, 1 = findings there,
    # 2 = usage / IO error (handled above).
    sys.exit(1 if verdict_for(findings, args.fail_on) else 0)


def cmd_redact(args):
    src = Path(args.path)
    if not src.exists():
        error_exit("file_not_found", f"path not found: {args.path}")
    out_root = Path(args.out) if args.out else Path("redacted-out")
    config = load_config(args.path)
    compiled = compile_ignore_patterns(config)
    written = 0
    for f in iter_files(src):
        display = str(f)
        if path_ignored(display, config):
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if is_binary_bytes(data):
            continue
        text = data.decode("utf-8", errors="replace")
        redacted = redact_text(text, display, config, compiled)
        if src.is_file():
            dest = out_root / f.name
        else:
            dest = out_root / f.relative_to(src)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(redacted, encoding="utf-8")
        written += 1
    print(f"Redacted copies written to {out_root}/ "
          f"({written} file(s)); originals untouched.")
    sys.exit(0)


CONFIG_TEMPLATE = {
    "ignore_paths": ["node_modules/*", "*.lock", "fixtures/*"],
    "ignore_patterns": [],
}

# AWS's published documentation-example key, assembled at runtime so
# the literal never sits in source (GitHub secret scanning flags it).
_DOC_AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"

_SAMPLE_TEMPLATE = """\
Agent run notes (sample — every value below is FAKE and planted on purpose)

The agent uploaded the build and logged the key it used:
  {KEY}

Run `secretscan scan sample-agent-output.txt` and watch it get caught.
Lines you *mean* to keep can carry the marker:  # secretscan:ignore
"""

SAMPLE_TEMPLATE = _SAMPLE_TEMPLATE.replace("{KEY}", _DOC_AWS_KEY)


def cmd_init(args):
    base = Path(args.dir) if args.dir else Path.cwd()
    base.mkdir(parents=True, exist_ok=True)
    cfg_path = base / CONFIG_NAME
    sample_path = base / "sample-agent-output.txt"
    for p in (cfg_path, sample_path):
        if p.exists() and not args.force:
            print(f"{p} exists — use --force to overwrite")
            return
    cfg_path.write_text(json.dumps(CONFIG_TEMPLATE, indent=2), encoding="utf-8")
    sample_path.write_text(SAMPLE_TEMPLATE, encoding="utf-8")
    print(f"created {cfg_path} and {sample_path}")
    print("try it:  secretscan scan sample-agent-output.txt")


def main():
    ap = argparse.ArgumentParser(
        prog="secretscan",
        description="Scan agent outputs for leaked secrets + PII "
                    "before they ship. Find secrets before git does.")
    ap.add_argument("--version", action="version",
                    version=f"secretscan {VERSION}")
    ap.add_argument("--no-color", action="store_true",
                    help="disable ANSI color output (this tool emits "
                         "none; accepted for family consistency)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a file, directory, or staged changes")
    s.add_argument("path", nargs="?", help="file or directory to scan")
    s.add_argument("--staged", action="store_true",
                   help="scan git staged changes (git diff --cached) instead")
    s.add_argument("--format", choices=("text", "json"), default="text",
                   help="report format (default: text)")
    s.add_argument("--fail-on", choices=SEVERITIES, default="high",
                   help="lowest severity that exits 1 (default: high)")
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("redact", help="write redacted copies of a file or tree")
    r.add_argument("path", help="file or directory to redact")
    r.add_argument("--out", metavar="DIR",
                   help="output directory (default: redacted-out)")
    r.set_defaults(fn=cmd_redact)

    i = sub.add_parser("init", help="scaffold .secretscan.json + a sample file")
    i.add_argument("--force", action="store_true")
    i.add_argument("--dir", help="directory to write the sample files into")
    i.set_defaults(fn=cmd_init)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
