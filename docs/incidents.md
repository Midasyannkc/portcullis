# Incident log

Every incident has two commits. The first adds a test that fails for the right reason; a later one fixes the code and the same test passes. Hashes below come from `git log`.

| # | Incident | Found by | Reproduce | Fix |
| --- | --- | --- | --- | --- |
| INC-1 | YAML 1.1 reads the `on:` key as boolean True, so pull_request_target workflows were never recognised as such | pwn-request test on a real-format workflow | `0eb7124` | `455071a` |
| INC-2 | Transposed-letter typosquats (lodahs, raect) were not flagged | typosquat test written from known squat patterns | `b418bf4` | `9217ce6` |
| INC-3 | Duplicate detection merged distinct bugs on the same asset and class | dedupe test against the synthetic corpus | `77d6032` | `d7970fb` |
| INC-4 | Brand used as a subdomain of an unrelated domain was missed | anti-scam corpus evaluation (4 false negatives) | `b420467` | `12b30be` |
| INC-5 | The digit 1 was read only as the letter l | anti-scam corpus evaluation | `ef0426a` | `0df509f` |
| INC-6 | Strong single drainer signals stayed under the detection threshold | anti-scam corpus evaluation (4 false negatives) | `71d831b` | `038b180` |
| INC-7 | A one-letter brand typo with no other signal, and the phrase 'limited time', raised false positives | anti-scam corpus evaluation (2 false positives) | `ce5a642` | `8c0789a` |
| INC-8 | Rust parse_frame panics on short input | deterministic fuzz test (20000 cases) and explicit short-frame test | `b557534` | `7ef02fb` |
| INC-9 | Rust amount truncated with `as u32` | exploit test | `9f944c3` | `55d8f34` |
| INC-10 | Rust MAC comparison returned at the first differing byte | exploit test using bytes examined as a deterministic stand-in for timing | `fb9c5eb` | `002c0e3` |
| INC-11 | TypeScript link preview fetched internal addresses (SSRF) | exploit test with 9 blocked targets | `f2b1a52` | `a4bdab2` |
| INC-12 | TypeScript note renderer did not escape HTML (stored XSS) | exploit test | `33315ae` | `b6db721` |
| INC-13 | TypeScript session tokens came from Math.random | exploit test that stubs Math.random | `1d2ce11` | `bc2e54a` |
| INC-14 | TypeScript transfer endpoint had no CSRF protection | exploit test | `db4cfbe` | `ea03bee` |
| INC-15 | Variant analysis: the webhook sender had the same SSRF as INC-11 | Semgrep taint rule derived from the INC-11 fix, swept over the whole target | `cd38ed2` | `93087f0` |
| INC-16 | Move treasury withdraw had no capability check | Move access-control rule (pattern only, no Move toolchain) | `266b43f` | `4157424` |
| INC-17 | Move rule flagged the real sui::coin test helpers | known-clean check on real Sui framework Move files | `18becc1` | `51cdab5` |
| INC-18 | Rust slice rule flagged the already-fixed parser | known-clean check on the fixed Treasury sources | `272a385` | `2eff74f` |
| INC-19 | Release workflow combined pull_request_target, an unpinned KEV action, shell injection and a secret | GitHub Actions analyzer on the Treasury workflow | `3f8367b` | `0a790df` |

### INC-1: YAML 1.1 reads the `on:` key as boolean True, so pull_request_target workflows were never recognised as such

The analyzer looked up wf['on'] and got nothing, so the pull_request_target plus untrusted checkout check (the pattern behind several real CI compromises) silently never ran. Both the string and boolean spellings are read now.

Reproduce `0eb7124`, fix `455071a`. Found by: pwn-request test on a real-format workflow.

### INC-2: Transposed-letter typosquats (lodahs, raect) were not flagged

Plain Levenshtein counts an adjacent swap as distance 2, and the threshold was 1. A single adjacent transposition is now an edit.

Reproduce `b418bf4`, fix `9217ce6`. Found by: typosquat test written from known squat patterns.

### INC-3: Duplicate detection merged distinct bugs on the same asset and class

Comparing titles alone marked 22 of 40 reports as duplicates when only 4 were. Distinct bugs on one asset were being closed as dupes, which would have cost a reporter a payout and the program a fix. A duplicate must now share asset, class and endpoint.

Reproduce `77d6032`, fix `d7970fb`. Found by: dedupe test against the synthetic corpus.

### INC-4: Brand used as a subdomain of an unrelated domain was missed

Only the registrable label was inspected, so sui.airdrop-claim.xyz scored 0. Every label left of the TLD is scanned now.

Reproduce `b420467`, fix `12b30be`. Found by: anti-scam corpus evaluation (4 false negatives).

### INC-5: The digit 1 was read only as the letter l

su1-rewards.xyz uses 1 for i. The skeleton now evaluates both readings.

Reproduce `ef0426a`, fix `0df509f`. Found by: anti-scam corpus evaluation.

### INC-6: Strong single drainer signals stayed under the detection threshold

Unlimited approvals, eth_sign and misleading signing prompts scored 2 or 3 against a threshold of 4. Each is a decisive signal on its own and is weighted at the threshold.

Reproduce `71d831b`, fix `038b180`. Found by: anti-scam corpus evaluation (4 false negatives).

### INC-7: A one-letter brand typo with no other signal, and the phrase 'limited time', raised false positives

waltrus-electric.com and a newsletter signup were flagged. Typo-only matches now need corroboration and 'limited time' is no longer an urgency signal.

Reproduce `ce5a642`, fix `8c0789a`. Found by: anti-scam corpus evaluation (2 false positives).

### INC-8: Rust parse_frame panics on short input

Indexing without a length check panicked for any frame under 24 bytes, a remote crash for a service that parses network frames. The fix returns ParseError::TooShort.

Reproduce `b557534`, fix `7ef02fb`. Found by: deterministic fuzz test (20000 cases) and explicit short-frame test.

### INC-9: Rust amount truncated with `as u32`

A transfer of 2^32+5 units was booked as 5. The fix uses u32::try_from and returns LedgerError::Overflow.

Reproduce `9f944c3`, fix `55d8f34`. Found by: exploit test.

### INC-10: Rust MAC comparison returned at the first differing byte

Response time would reveal how many leading bytes of a MAC guess are right. The fix accumulates the difference over all bytes. The test proves equal work, not wall-clock timing.

Reproduce `fb9c5eb`, fix `002c0e3`. Found by: exploit test using bytes examined as a deterministic stand-in for timing.

### INC-11: TypeScript link preview fetched internal addresses (SSRF)

Only startsWith('http') was checked, so cloud metadata, loopback, private ranges, file: and numeric hosts were fetched. A shared assertPublicHttps policy now applies.

Reproduce `f2b1a52`, fix `a4bdab2`. Found by: exploit test with 9 blocked targets.

### INC-12: TypeScript note renderer did not escape HTML (stored XSS)

User text was interpolated into a template literal. The fix escapes & < > and quotes.

Reproduce `33315ae`, fix `b6db721`. Found by: exploit test.

### INC-13: TypeScript session tokens came from Math.random

Math.random is predictable from a few outputs. Tokens now come from crypto.randomBytes.

Reproduce `1d2ce11`, fix `bc2e54a`. Found by: exploit test that stubs Math.random.

### INC-14: TypeScript transfer endpoint had no CSRF protection

Cookie authentication alone let a cross-site form post move funds. A per-session CSRF token header is now required.

Reproduce `db4cfbe`, fix `ea03bee`. Found by: exploit test.

### INC-15: Variant analysis: the webhook sender had the same SSRF as INC-11

The INC-11 fix covered linkPreview only. The rule found notifyMerchant, which fetched a merchant supplied URL with the same weak check. Both now share one policy, which is the point of variant analysis: close the class, not the instance.

Reproduce `cd38ed2`, fix `93087f0`. Found by: Semgrep taint rule derived from the INC-11 fix, swept over the whole target.

### INC-16: Move treasury withdraw had no capability check

Anyone could call the public withdraw function and take funds. It now requires &AdminCap. The Move code was never compiled or run here.

Reproduce `266b43f`, fix `4157424`. Found by: Move access-control rule (pattern only, no Move toolchain).

### INC-17: Move rule flagged the real sui::coin test helpers

&mut TxContext matched the shared-object argument pattern. It is excluded now. This is the known-clean check the posting asks for doing its job.

Reproduce `18becc1`, fix `51cdab5`. Found by: known-clean check on real Sui framework Move files.

### INC-18: Rust slice rule flagged the already-fixed parser

The length guard sits inside an if, which the not-inside pattern did not recognise. A `if buf.len() < N` guard now suppresses the rule.

Reproduce `272a385`, fix `2eff74f`. Found by: known-clean check on the fixed Treasury sources.

### INC-19: Release workflow combined pull_request_target, an unpinned KEV action, shell injection and a secret

Four critical or high findings on one file. The fix is tag triggered, pinned to a real commit SHA, passes the ref through env, scopes permissions, uses a protected environment and publishes with provenance.

Reproduce `3f8367b`, fix `0a790df`. Found by: GitHub Actions analyzer on the Treasury workflow.
