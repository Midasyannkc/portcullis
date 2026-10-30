# Treasury (review target)

Invented code with deliberately seeded flaws, used to exercise Portcullis review tooling.
Nothing here is a real Mysten Labs system.  Each flaw has an exploit test that fails on the
vulnerable commit and passes after the fix (see docs/incidents.md).

- `treasury-rs`   Rust, std only: frame parser, ledger conversion, MAC compare
- `treasury-ts`   TypeScript (Node 22 type stripping): link preview, webhook, renderer, sessions
- `treasury-move` Move module (pattern-checked only, no Move toolchain in the build sandbox)
- `treasury-ci`   GitHub Actions release workflow
