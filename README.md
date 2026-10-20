# SecretScan 🔒

**AI agents paste things — API keys into run logs, tokens into traces, test card numbers into sample outputs — and then someone commits the whole folder.**

SecretScan scans agent outputs and artifacts for leaked secrets and PII, fails CI at the severity you set, and can write redacted copies that are safe to share. (Values in its own reports are always truncated, as below.)

*Part of **AgentForge** — verify AI-agent work before you ship it.*
*The family: [AgentProof](https://github.com/maticcretic-commits/agentproof) · [PromptRE](https://github.com/maticcretic-commits/promptre) · [AgentCI](https://github.com/maticcretic-commits/agentci) · [SecretScan](https://github.com/maticcretic-commits/secretscan) · [CostLedger](https://github.com/maticcretic-commits/costledger) · [SchemaGuard](https://github.com/maticcretic-commits/schemaguard) · [SkillAudit](https://github.com/maticcretic-commits/skillaudit) · [PromptDiff](https://github.com/maticcretic-commits/promptdiff) · [TraceTape](https://github.com/maticcretic-commits/tracetape) · [PromptLint](https://github.com/maticcretic-commits/promptlint) · [ClaimCheck](https://github.com/maticcretic-commits/claimcheck) · [TrustBadge](https://github.com/maticcretic-commits/trustbadge)*

```bash
$ secretscan scan examples/agent-output-with-secrets.md
```

```
====================================================================
SecretScan — scan report
====================================================================
Source:  examples/agent-output-with-secrets.md
Scanned: 1 file(s) · 9 finding(s)

## examples/agent-output-with-secrets.md
  line 5     🟠 HIGH     [aws-access-key] AWS access key — AKIAIOSFOD…
  line 6     🔴 CRITICAL [aws-secret-key] AWS secret access key — aws_secret…
  line 7     🟠 HIGH     [github-token] GitHub token — ghp_FakeFa…
  line 8     🔴 CRITICAL [stripe-key] Stripe live secret key — sk_live_Fa…
  line 9     🟠 HIGH     [credit-card] Credit card number (Luhn-verified) — 4242 4242 …
  …
❌ FAIL — 5 finding(s) at or above 'high'
```

*Exit code 1 — five findings at or above the default `high` fail threshold. The sample file's secrets are planted fakes; the same file also carries an allowlisted line that never appears.*

## Install

```bash
pipx install git+https://github.com/maticcretic-commits/secretscan
# or, into the current environment:
pip install git+https://github.com/maticcretic-commits/secretscan
```

Then run it as `secretscan …` (Python 3.9+, no dependencies — stdlib only).
PyPI release planned; until then, the git URL above is the install path.

From source — it is a single file, so no install is needed at all:

```bash
git clone https://github.com/maticcretic-commits/secretscan
cd secretscan
python src/secretscan.py …
```

## What it catches

| Check | Finds | Severity |
|-------|-------|----------|
| `private-key` | PEM private-key blocks (`-----BEGIN … PRIVATE KEY-----`) | 🔴 critical |
| `stripe-key` | Stripe live secret / webhook keys (`sk_live_`, `rk_live_`, `whsec_`) | 🔴 critical |
| `aws-secret-key` | `aws_secret_access_key` assignments | 🔴 critical |
| `aws-access-key` | AWS access keys (`AKIA…`, `ASIA…`, …) | 🟠 high |
| `github-token` | GitHub tokens (`ghp_`, `gho_`, `github_pat_`, …) | 🟠 high |
| `openai-key` | OpenAI-style keys (`sk-ant-`, `sk-proj-`, `sk-…`) | 🟠 high |
| `slack-token` | Slack tokens (`xoxb-`, `xoxp-`, `xapp-`) | 🟠 high |
| `google-api-key` | Google API keys (`AIza…`) | 🟠 high |
| `google-oauth-token` | Google OAuth tokens (`ya29.…`) | 🟠 high |
| `credit-card` | Card numbers, verified with the Luhn checksum | 🟠 high |
| `jwt` | JSON Web Tokens | 🟡 medium |
| `generic-credential` | `password = "…"`, `api_key = "…"` style assignments with token-like values | 🟡 medium |
| `ssn` | US Social Security numbers | 🟡 medium |
| `high-entropy` | Strings with Shannon entropy ≥ 4.5 and length ≥ 20 | 🔵 low |
| `phone` | Phone numbers | 🔵 low |

References are not secrets: `api_key = os.environ["API_KEY"]`,
`${API_TOKEN}`, and placeholders like `changeme` are skipped, not flagged.

## Quick start

```bash
# Scan a file or a whole directory (recursive; binary files and .git/ skipped):
secretscan scan outputs/

# Machine-readable output + a custom fail threshold for CI:
secretscan scan outputs/ --format json
secretscan scan outputs/ --fail-on critical

# Pre-commit style: scan only what's staged:
secretscan scan --staged

# Write redacted copies (originals are never modified):
secretscan redact outputs/ --out shareable/

# Scaffold a config + a sample file with a planted fake key:
secretscan init
secretscan scan sample-agent-output.txt
```

Exit codes: `0` = no findings at or above `--fail-on` (default
`high`), `1` = findings at or above it, `2` = usage / IO error.
Drop it in GitHub Actions or a pre-commit hook.

## Allowlist

Two ways to keep intentional fakes quiet:

- **Per line:** put `secretscan:ignore` anywhere on the line — that
  line is skipped by both `scan` and `redact`.
- **Per project:** a `.secretscan.json` next to your work:

```json
{
  "ignore_paths": ["fixtures/*", "*.lock"],
  "ignore_patterns": ["AKIAIOSFODNN7EXAMPLE"]
}
```

`ignore_paths` are globs matched against file paths; `ignore_patterns`
are regexes matched against each line.

## Example

From `examples/` — one trace with planted (fake) secrets, one clean:

```
$ secretscan scan examples/agent-output-with-secrets.md
====================================================================
SecretScan — scan report
====================================================================
Source:  examples/agent-output-with-secrets.md
Scanned: 1 file(s) · 9 finding(s)

## examples/agent-output-with-secrets.md
  line 5     🟠 HIGH     [aws-access-key] AWS access key — AKIAIOSFOD…
  line 6     🔴 CRITICAL [aws-secret-key] AWS secret access key — aws_secret…
  line 7     🟠 HIGH     [github-token] GitHub token — ghp_FakeFa…
  line 8     🔴 CRITICAL [stripe-key] Stripe live secret key — sk_live_Fa…
  line 9     🟠 HIGH     [credit-card] Credit card number (Luhn-verified) — 4242 4242 …
  line 10    🟡 MEDIUM   [jwt] JSON Web Token — eyJhbGciOi…
  line 11    🟡 MEDIUM   [ssn] US Social Security number — 123-45-678…
  line 12    🔵 LOW      [phone] Phone number — 415-555-01…
  line 13    🔵 LOW      [high-entropy] High-entropy string — Xk9mQ2wZ8v…

❌ FAIL — 5 finding(s) at or above 'high'
```

(The tenth line of that file carries a deliberate fake too — it is
allowlisted with `secretscan:ignore`, so it never appears.)

```
$ secretscan scan examples/agent-output-clean.md
Scanned: 1 file(s) · 0 finding(s)

✅ Clean — no secrets or PII found.
```

And `secretscan redact` turns the dirty trace into a shareable one —
every secret replaced in place, originals untouched:

```
- GitHub token for the release: [REDACTED:github-token]
- Test card used for the sample purchase: [REDACTED:credit-card]
```

## Why

Agents are prolific and indiscreet: a single run can scatter working
credentials across logs, traces, and generated files faster than any
human would. Review catches what people notice; SecretScan catches
what they don't — in the 30 seconds before the commit, not in the
incident review after it.

## Limitations

- Pattern- and entropy-based: novel or obfuscated secret formats can slip
  through, and high-entropy strings (hashes, IDs) can false-positive — the
  allowlist exists for the fakes you keep on purpose.
- It finds secret-*shaped* strings; it cannot tell a live key from a
  revoked one.
- Scanning is line-based: a secret split across lines, or encoded so it no
  longer matches its format, may not be recognised.

## Exit codes & JSON output

All AgentForge tools share one contract (full text in
[CONVENTIONS.md](CONVENTIONS.md)):

| Code | Meaning |
|------|---------|
| `0` | Clean / PASS — no findings at or above the tool's fail threshold |
| `1` | Findings / FAIL — the tool ran fine; the answer is “no” |
| `2` | Caller error — bad arguments, missing or unreadable input |
| `3` | Environment error — the tool itself could not run |

On a caller error the tool also prints one JSON line to stderr:
`{"error": {"code": "file_not_found", "message": "no such file: x"}}`.

JSON output (`--format json`) always carries the family envelope —
`{"tool": "secretscan", "version": "1.0.0", "schema_version": 1}` — alongside
the tool's own payload keys, unchanged.

## Part of AgentForge

SecretScan is one of the 12 tools in the [AgentForge](https://github.com/maticcretic-commits) family — offline, stdlib-only tools to **verify AI-agent work before you ship it**:

- **AgentProof** — verify agent work — [github.com/maticcretic-commits/agentproof](https://github.com/maticcretic-commits/agentproof)
- **PromptRE** — reverse-engineer agent prompts — [github.com/maticcretic-commits/promptre](https://github.com/maticcretic-commits/promptre)
- **AgentCI** — regression harness for agents — [github.com/maticcretic-commits/agentci](https://github.com/maticcretic-commits/agentci)
- **SecretScan** — scan agent outputs for leaked secrets (this repo)
- **CostLedger** — cost accounting for agent runs — [github.com/maticcretic-commits/costledger](https://github.com/maticcretic-commits/costledger)
- **SchemaGuard** — validate agent outputs against their contracts — [github.com/maticcretic-commits/schemaguard](https://github.com/maticcretic-commits/schemaguard)
- **SkillAudit** — audit agent skills for hidden instructions and quality — [github.com/maticcretic-commits/skillaudit](https://github.com/maticcretic-commits/skillaudit)
- **PromptDiff** — diff prompt versions — [github.com/maticcretic-commits/promptdiff](https://github.com/maticcretic-commits/promptdiff)
- **TraceTape** — the canonical run tape — [github.com/maticcretic-commits/tracetape](https://github.com/maticcretic-commits/tracetape)
- **PromptLint** — lint prompts for quality defects — [github.com/maticcretic-commits/promptlint](https://github.com/maticcretic-commits/promptlint)
- **ClaimCheck** — audit agent reports against their evidence — [github.com/maticcretic-commits/claimcheck](https://github.com/maticcretic-commits/claimcheck)
- **TrustBadge** — one trust score and badge for the whole family — [github.com/maticcretic-commits/trustbadge](https://github.com/maticcretic-commits/trustbadge)

AgentProof checks what an agent *did*; PromptRE checks what it was *told*; AgentCI checks it still *works* after you change it; SecretScan checks that nothing *leaked*; CostLedger checks what it *cost*; SchemaGuard checks the output still *fits the contract*; SkillAudit checks the skill was *safe to install*; PromptDiff checks what the prompt change *changed*; TraceTape keeps the whole run on *tape*; PromptLint keeps the prompt itself *linted clean*; ClaimCheck makes sure every claim is *backed*; TrustBadge puts the family's score *on one badge*.

## License

MIT
