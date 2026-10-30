# Architecture

```
data/raw        real: workflows, Sui Move, npm metadata/tarballs/registry keys, GHSA, RustSec, CISA KEV
data/synthetic  invented: bounty reports, anti-scam corpus and holdout
portcullis/
  supplychain/  actions (CI), npm (signatures, integrity, scripts, typosquat), lockfile, provenance
  intel.py      compromised versions and RustSec from real advisories
  bounty/       triage (severity, dedupe, SLA, budget), fixcheck (PoC replay)
  audit/        engagement schedule and findings state machine
  abuse/        lookalike domains, phishing pages, drainer JS and Move
  report.py     runs everything, writes out/report.json and docs/REPORT.md
rules/          Semgrep rules derived from fixed bugs, plus vulnerable exemplars
target/         Treasury: Rust, TypeScript, Move, CI (invented, seeded flaws)
```

Design rules that carry across modules:

1. **Deterministic code decides.** Bounty severity comes from structured fields only. Report prose is untrusted, may be read by a model to draft a reply, and is never an input to severity, payout or state changes.
2. **Every detector has a known-clean check on real data** (real workflows, real tarballs, real Sui framework Move). A rule that cannot stay quiet on real code is not shipped.
3. **Every fix is two commits.** A failing test first, then the fix. `scripts/verify_incidents.py` re-runs both in scratch worktrees.
4. **Variant analysis closes the class.** A rule derived from one fix is swept over everything; INC-15 is what that found.
