# SecretScan 🔒

**Catch leaked secrets in agent outputs before they ship.**

Find secrets before git does.

AI agents paste things. API keys into run logs, tokens into traces,
test card numbers into sample outputs, private keys into "temporary"
debug files — and then someone commits the whole folder. SecretScan
scans agent outputs and artifacts for leaked secrets and PII, and can
write redacted copies that are safe to share.

Offline and dependency-free: pattern detectors for known token
formats, a Luhn check for card numbers, Shannon-entropy candidates,
and an allowlist for the fakes you keep on purpose. Scanning is
line-based, so JSONL agent traces report exact per-record line numbers.

```bash
python src/secretscan.py scan agent-run.log
python src/secretscan.py scan --staged        # pre-commit: staged changes only
python src/secretscan.py redact agent-run.log --out shareable/
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

## Part of AgentForge

SecretScan is the fourth tool in the [AgentForge](https://github.com/maticcretic-commits)
trust layer for AI agents:

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

AgentProof checks what an agent *did*; PromptRE checks what it was *told*; AgentCI checks it still *works* after you change it; SecretScan checks that nothing *leaked*; CostLedger checks what it *cost*; SchemaGuard checks the output still *fits the contract*; SkillAudit checks the skill was *safe to install*; PromptDiff checks what the prompt change *changed*; TraceTape keeps the whole run on *tape*; PromptLint keeps the prompt itself *linted clean*.

## License

MIT
