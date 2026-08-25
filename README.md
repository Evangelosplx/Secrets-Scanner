# secrets-scanner

A git-aware secrets scanner that finds leaked credentials — API keys, tokens, passwords and
private keys — not only in your current code but across the **entire commit history** of a
repository. It combines **regex signatures** with **Shannon-entropy analysis**, aggressively reduces
false positives, assigns a **red/yellow/green severity** to every finding, and can optionally
**verify live** whether a recognised token is still active.

> Built as a defensive security tool for auditing your own repositories before an attacker does.

---

## Why this matters

Secret leakage through source control is one of the most common and most damaging real-world
security failures. Two facts make it especially dangerous:

1. **Deleting a secret from your code does not remove it.** Git is an append-only history. If you
   commit an AWS key today and "fix" it tomorrow by deleting the line, the key still sits in the old
   commit forever. Anyone who clones the repo — or reads a public mirror — can walk the history and
   recover it. A scanner that only looks at the current working tree gives you a false sense of
   safety.
2. **Leaked keys are exploited fast.** Automated bots continuously scrape public git hosts for
   credential patterns. A live key can be abused (crypto mining, data exfiltration, sending spam)
   within minutes of being pushed.

This tool exists to catch those secrets **first**, from the defender's side, and to tell you exactly
where each one lives (file, line, commit) and how worried you should be about it.

---

## Features

- **Regex signatures** for well-known providers: AWS access keys, GitHub tokens, Stripe live keys,
  Google API keys, PEM private keys, plus a generic `password = "..."` / `api_key = "..."` catch-all.
- **Shannon-entropy analysis** to catch high-randomness secrets that match *no* known pattern.
- **Full git-history scan** — every version of every changed file across all commits, with each
  finding attributed to the commit it appears in. `--no-history` limits it to current files.
- **False-positive reduction** — values containing `example`, `test`, `dummy`, `placeholder`, `foo`,
  `xxx`, … , values inside comments, and values in test/example/doc files are **down-ranked** (never
  silently dropped) with a recorded reason.
- **Optional live verification** (`--live-verify`, opt-in) — for recognised token types (GitHub
  first) makes a single API call to check whether the credential is still active.
- **Severity scoring** — combines pattern confidence, entropy, file/line context, and live-verify
  result into a `RED` / `YELLOW` / `GREEN` score.
- **Clean reporting** — a colored `rich` table in the terminal, or machine-readable JSON with
  `--json` for CI pipelines and other tooling. Secrets are always **masked** in output.
- **CI-friendly** — exits non-zero when any `RED` finding remains.

---

## How detection works

### 1. Regex signatures

Most credentials have a recognisable shape. The scanner ships a table of patterns
(`secrets_scanner/patterns.py`), each with a *base confidence* used later in scoring:

| Secret type        | Pattern (simplified)                              | Confidence |
| ------------------ | ------------------------------------------------- | ---------- |
| AWS Access Key     | `AKIA[0-9A-Z]{16}`                                | high       |
| GitHub Token       | `gh[pousr]_[A-Za-z0-9]{36,}`                       | high       |
| Stripe Secret Key  | `sk_live_[0-9A-Za-z]{24,}`                         | high       |
| Google API Key     | `AIza[0-9A-Za-z_\-]{35}`                           | high       |
| Private Key        | `-----BEGIN … PRIVATE KEY-----`                    | high       |
| Generic Secret     | `(password|secret|token|api_key…) = "……"`         | low (noisy)|

The generic pattern is deliberately low-confidence: it catches things the provider patterns miss,
but on its own it produces a lot of noise, so scoring treats it cautiously. When a provider signature
and the generic pattern match the *same* value, only the provider signature is kept.

### 2. Shannon-entropy analysis

Signatures only catch secrets whose format you already know. To catch the rest, the scanner measures
**Shannon entropy** — the average number of bits of information per character:

```
H = - Σ  p(c) · log2 p(c)
```

where `p(c)` is the frequency of each distinct character in a string. The intuition:

- A human-written identifier like `getUserProfile` is highly predictable → **low entropy**.
- `"aaaaaaaa"` has zero entropy (no uncertainty at all).
- A real random key like `wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY` packs close to the maximum
  information per character → **high entropy**.

The scanner carves each line into long base64/hex-like runs and flags those whose entropy exceeds a
threshold (≈ 4.5 bits/char for base64, ≈ 3.0 for hex — tuned below the theoretical ceiling of each
alphabet but above what ordinary code and prose produce). See `secrets_scanner/entropy.py`.

### 3. False-positive reduction & scoring

A raw match is not a verdict. Each finding is scored (`secrets_scanner/scoring.py`) by starting from
the pattern's confidence (or an entropy baseline) and then applying context:

- **placeholder/test keyword** in the value or line → strong down-rank,
- **located in a test/example/doc file** → medium down-rank,
- **inside a comment** → small down-rank,
- **live-verified ACTIVE** → forced to maximum severity; **REVOKED** → capped low.

The final score maps to a traffic light:

- 🔴 **RED** — confident and/or verified-live secret in real code. Act now.
- 🟡 **YELLOW** — suspicious, high-entropy, or a real pattern sitting in a test/comment. Review it.
- 🟢 **GREEN** — almost certainly a placeholder/example. Informational.

Every finding records the human-readable **reasons** behind its score, so nothing is a black box.

### 4. Live verification (opt-in)

With `--live-verify`, recognised tokens are checked against their provider's API. For GitHub this is
a single `GET https://api.github.com/user` using the token: `200` means the token is **active**
(escalated to RED), `401/403` means it is **revoked**. This is the only feature that sends data over
the network, it is **off by default**, and it uses only the Python standard library. Any network
error degrades gracefully to "unknown" — it never crashes a scan.

> ⚠️ Live verification transmits the discovered credential to a third-party API. Only use it on
> secrets you are authorised to test.

---

## Installation

Requires **Python 3.10+** and **git** on your `PATH`.

```bash
git clone <this-repo>
cd secrets-scanner
python -m pip install -r requirements.txt        # runtime (just: rich)
python -m pip install -r requirements-dev.txt     # + pytest, for running tests
```

---

## Usage

```bash
# Scan a repository's working tree AND full history (colored table)
python -m secrets_scanner /path/to/repo

# Scan the current directory
python -m secrets_scanner .

# Only current files, skip history (much faster)
python -m secrets_scanner /path/to/repo --no-history

# Machine-readable JSON, only RED findings (great for CI)
python -m secrets_scanner /path/to/repo --json --min-severity red

# Opt-in: check whether recognised tokens (e.g. GitHub) are still live
python -m secrets_scanner /path/to/repo --live-verify
```

### Options

| Flag                       | Description                                                       |
| -------------------------- | ---------------------------------------------------------------- |
| `repo`                     | Path to the git repository (default: `.`).                       |
| `--json`                   | Emit JSON instead of the colored table.                          |
| `--no-history`             | Scan only current files; skip commit history.                    |
| `--live-verify`            | Opt-in live check of recognised tokens (makes network calls).    |
| `--min-severity {green,yellow,red}` | Only report findings at or above this severity.         |
| `--entropy-threshold BITS` | Override the base64 entropy threshold (bits/char, default 4.5).  |
| `--version`                | Print the version.                                               |

**Exit codes:** `0` — no RED findings; `1` — at least one RED finding (use as a CI gate); `2` — the
target is not a git repository / git error.

### Example output

```
                               Potential Secrets
+---------------------------------------------------------------------------------------+
| Severity | Type            | File               | Line | Commit       | Secret (masked) |
|----------+-----------------+--------------------+------+--------------+-----------------|
|   RED    | GitHub Token    | config.py          |    2 | f66c89a5bc   | ghp_********2345 |
|   RED    | AWS Access Key  | config.py          |    1 | f66c89a5bc   | AKIA********K3PL |
|  YELLOW  | Stripe Key      | config.env.example |    1 | working tree | sk_l********p7dc |
|  GREEN   | GitHub Token    | config.py          |    3 | working tree | ghp_********xxxx |
+---------------------------------------------------------------------------------------+
```

Here the AWS and GitHub keys were **deleted** from the current code but recovered from an old commit
(`f66c89a5bc`) and correctly flagged RED; the Stripe key in an `.example` file is down-ranked to
YELLOW; and a `ghp_xxxx…` placeholder is GREEN.

---

## Project layout

```
secrets_scanner/
├── entropy.py          # Shannon entropy + high-entropy substring extraction
├── patterns.py         # regex signatures + confidence weights
├── detectors.py        # per-line detection (regex + entropy) -> RawMatch
├── false_positives.py  # context analysis (keywords, comments, test files)
├── scoring.py          # combine confidence/entropy/context/live -> severity
├── verify.py           # opt-in live verification (GitHub) via urllib
├── scanner.py          # orchestration: text -> scored Finding objects
├── git_history.py      # subprocess git access + whole-repo scan + dedup
├── report.py           # rich terminal renderer + JSON serializer
├── models.py           # Finding / ScanResult / Severity / masking
└── cli.py              # argparse command-line interface
tests/                  # unit + end-to-end tests (pytest)
```

**Design principle:** detection and scoring are *pure* (strings in → findings out). All git and
network I/O is isolated in `git_history.py` and `verify.py`, so the core logic is fully unit-testable
without a real repository or network access.

---

## Running the tests

```bash
python -m pytest
```

The suite covers entropy math, every regex signature, false-positive/context rules, severity
scoring, and an **end-to-end git test** that plants a fake secret in one commit, deletes it in the
next, and proves the scanner still recovers it from history and attributes it to the right commit.

---

## Limitations & scope

- Detection is line-based, so a multi-line private-key *body* is flagged by its header line.
- Entropy analysis is inherently heuristic; thresholds are tunable via `--entropy-threshold`.
- Live verification currently supports GitHub tokens; the `verify.py` registry is designed to be
  extended to more providers.
- This is an auditing/education tool. Use it only on repositories you are authorised to scan, and
  use `--live-verify` only on credentials you are authorised to test.

## License

MIT.
