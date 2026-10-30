# AI development log

Built in one session with Claude as the coding assistant. Christian Kouadio Kouassi is the author and owner of every commit.

## What the assistant generated

The Python source, tests, synthetic datasets and their generators, the Treasury target code (Rust, TypeScript, Move, CI), the Semgrep rules, the report generator, the deck and this log.

## What was checked, and how

- **Real data, real tools.** npm registry signatures were verified with the registry's published ECDSA P-256 keys (40 of 40 verify) and tarball hashes against their sha512 integrity (10 of 10). Semgrep, cargo and Node were run and their output parsed. Numbers in the README come from `python -m portcullis`.
- **Every incident has a failing test first.** `scripts/verify_incidents.py` checks out each reproduce and fix commit in a scratch worktree and runs the touched tests: reproduce fails, fix passes, for all 19.
- **Several incidents were not planned.** INC-2 to INC-7 and INC-17 and INC-18 came from running detectors against corpora and real data, not from the design. INC-15 came from sweeping a rule derived from INC-11.
- **Wrong first attempts.** A test expected the wrong business day around Thanksgiving. A first dedupe test used wrong report ids. A first Semgrep guard pattern did not parse (`$OP` is not allowed in that position).
- **Holdout.** The anti-scam tuned corpus scores 1.0 because it was tuned against. A holdout written afterwards scores recall 0.923 with one documented miss.

## What was not verified

- Move was never compiled or run. The Move rule and fix are pattern-checked only.
- `semgrep --validate` needs a download the sandbox blocks. Rules were validated by loading them in real scans.
- Bounty reports, the audit engagement, the anti-scam corpus and all malicious fixtures are invented and inert. Nothing was submitted to a bounty platform, Endor Labs, a wallet or a chain.
- No LLM is called. The injection tests show the deterministic decision ignores drafted severities, using a scripted stand-in for a model.
- The popular-package list for typosquats is hand curated (142 names), not download ranked.
- The MAC test counts bytes examined as a stand-in for timing; it does not measure wall-clock time.
- Workflow sweep numbers are aggregate counts over 13 public workflows, not an audit of those projects.
