# Data sources and disclosed substitutions

All files under data/raw were downloaded unmodified by `scripts/fetch_data.py`. `data/raw/MANIFEST.json` lists the URL, byte count and SHA-256 of each.

## Real data

| Path | What it is | Source |
| --- | --- | --- |
| data/raw/kev.json | CISA Known Exploited Vulnerabilities catalog (version 2026.10.29 at download) | github.com/cisagov/kev-data |
| data/raw/workflows/ | 13 real GitHub Actions workflow files from public repositories, including two from MystenLabs/sui | raw.githubusercontent.com |
| data/raw/move/ | 5 real Move modules from the Sui framework (coin, balance, transfer, vec_map, kiosk) | MystenLabs/sui |
| data/raw/advisories/ | 7 real GitHub advisories for supply chain compromises (tj-actions/changed-files, the debug, color-name, backslash and prebid npm takeovers, MetaMask SDK) | github/advisory-database |
| data/raw/rustsec/ | 4 real RustSec advisories, including RUSTSEC-2022-0093 (ed25519-dalek double public key oracle) | rustsec/advisory-db |
| data/raw/npm/latest/ | registry metadata (`/<name>/latest`) for 40 popular npm packages, including `dist.integrity` and `dist.signatures` | registry.npmjs.org |
| data/raw/npm/tarballs/ | 10 real package tarballs | registry.npmjs.org |
| data/raw/npm/registry_keys.json | the npm registry's public signing keys | registry.npmjs.org/-/npm/v1/keys |

## Real tools, run for real

Semgrep (local rules, taint mode, languages: TypeScript, Rust, Python and generic for Move), cargo and rustc (the Rust crate is compiled and its tests run), Node 22 (the TypeScript service tests run with built-in type stripping), PyYAML, and `cryptography` for ECDSA P-256 verification of npm registry signatures and Ed25519 build provenance.

## Disclosed synthetic data

The bug bounty reports, the audit report, the lookalike-domain and phishing-page corpus, the drainer samples, the malicious package fixtures, the lockfiles, the Treasury target code (Rust, TypeScript, Move, workflows) and the popular-package name list used for typosquat checks (curated by hand, about 150 names) are invented. Malicious fixtures are inert strings and never execute anything. Brand names in the protected-brand list are used only as reference values for detection.

## Not done

No live bug bounty platform, audit firm, Endor Labs, wallet or blockchain node. Semgrep registry and OSV are unreachable from this environment, so Semgrep uses local rules. The Move code is checked by patterns, not compiled or proven: no Move toolchain was available. The LLM interface is exercised only with scripted stand-ins.
