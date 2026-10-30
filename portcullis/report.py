"""Run every Portcullis module over the data and write out/report.json and docs/REPORT.md.
Deterministic: sorted keys, fixed as-of date, no clocks, no absolute paths."""
import json, subprocess, tarfile, io
from collections import Counter
from datetime import date
from pathlib import Path

from portcullis import intel
from portcullis.abuse import detect as D
from portcullis.audit import Engagement, Finding as AF
from portcullis.bounty import fixcheck, triage as T
from portcullis.supplychain import actions, npm

ROOT = Path(__file__).resolve().parents[1]
ASOF = date(2026, 10, 29)


def supply():
    kev = actions.kev_actions()
    sweep = actions.sweep(str(ROOT / "data/raw/workflows"), kev)
    sev = Counter(f.severity for fs in sweep.values() for f in fs)
    rules = Counter(f.rule for fs in sweep.values() for f in fs)
    keys = npm.load_keys()
    metas = [json.loads(p.read_text()) for p in sorted((ROOT / "data/raw/npm/latest").glob("*.json"))]
    signed = [m for m in metas if m.get("dist", {}).get("signatures")]
    ok = sum(npm.verify_signature(m, keys) for m in signed)
    tb = sorted((ROOT / "data/raw/npm/tarballs").glob("*.tgz"))
    integ = 0; clean = 0
    for t in tb:
        name, ver = t.stem.rsplit("-", 1)
        meta = next(m for m in metas if m["name"] == name and m["version"] == ver)
        data = t.read_bytes()
        integ += npm.verify_integrity(meta, data)
        clean += not [f for f in npm.analyze_tarball(data, t.stem) if f.severity in ("high", "critical")]
    scripts = sorted(m["name"] for m in metas if any(k in (m.get("scripts") or {}) for k in npm.LIFECYCLE))
    bad = intel.compromised_versions()
    return {"workflows_scanned": len(sweep), "workflow_findings_by_severity": dict(sorted(sev.items())),
            "workflow_findings_by_rule": dict(sorted(rules.items())), "workflows_with_no_findings": sorted(k for k, v in sweep.items() if not v),
            "kev_github_actions_known": len(kev), "npm_signatures_verified": f"{ok}/{len(signed)}", "npm_tarball_integrity_verified": f"{integ}/{len(tb)}",
            "real_tarballs_with_no_high_findings": f"{clean}/{len(tb)}", "real_packages_with_lifecycle_scripts": scripts,
            "compromised_versions_known": sorted(f"{n}@{v} ({g})" for (n, v), g in bad.items()),
            "rustsec_advisories": [a["id"] for a in intel.rustsec()]}


def bounty():
    reports = T.load()
    rows = T.decide(reports)
    sev = Counter(r["severity"] for r in rows if not r["duplicate_of"])
    b = T.Budget(10**9)
    for r in rows:
        b.approve(r["id"], r["severity"], duplicate=bool(r["duplicate_of"]))
    inj = [r["id"] for r in rows if r["injection_flag"]]
    return {"reports": len(rows), "duplicates": sum(1 for r in rows if r["duplicate_of"]), "unique_by_severity": dict(sorted(sev.items())),
            "recurring_classes": T.recurring(rows), "injection_flagged": inj,
            "injection_severity_after_decision": [r["severity"] for r in rows if r["id"] in inj],
            "total_payout_usd": b.paid,
            "fix_validation": {c: fixcheck.validate(c)["accepted"] for c in sorted(fixcheck.PAIRS)}}


def audit():
    e = Engagement("Example Audit Firm (synthetic)", ["treasury-move", "treasury-rs"], date(2026, 11, 2), 15)
    for i, (t, s) in enumerate([("Missing capability check", "critical"), ("Panic on short frame", "high"), ("Lossy cast", "medium"), ("Doc typo", "low")], 1):
        e.findings.append(AF(f"AUD-{i}", t, s))
    f = e.findings
    f[0].move("acknowledged", ASOF); f[0].move("fix-in-progress", ASOF); f[0].move("fix-submitted", ASOF, fix_commit="4157424")
    f[0].move("verified-fixed", ASOF, retest_commit="4157424", retest_passed=True)
    f[1].move("acknowledged", ASOF)
    return e.summary(ASOF)


def abuse():
    base = [tuple(s) for s in json.loads((ROOT / "data/synthetic/abuse_corpus.json").read_text())]
    hold = [tuple(s) for s in json.loads((ROOT / "data/synthetic/abuse_holdout.json").read_text())]
    eb, eh = D.evaluate(base), D.evaluate(hold)
    mv = [D.move_score(p.read_text())[0] for p in sorted((ROOT / "data/raw/move").glob("*.move"))]
    js = 0; n = 0
    for t in sorted((ROOT / "data/raw/npm/tarballs").glob("*.tgz")):
        with tarfile.open(t) as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith((".js", ".mjs", ".cjs")):
                    n += 1; js += D.js_score(tf.extractfile(m).read().decode("utf8", "ignore"))[0] >= 4
    strip = lambda e: {k: v for k, v in e.items() if k != "misses"}
    return {"tuned_corpus": {**strip(eb), "n": len(base)}, "holdout": {**strip(eh), "n": len(hold), "misses": [m[2] for m in eh["misses"]]},
            "real_sui_move_files_flagged": f"{sum(s >= 4 for s in mv)}/{len(mv)}", "real_npm_js_files_flagged": f"{js}/{n}"}


def review():
    p = subprocess.run(["semgrep", "--config", str(ROOT / "rules/portcullis.yml"), "--metrics=off", "--disable-version-check", "--json", "--quiet",
                        "rules/exemplars", "target", "data/raw/move"], cwd=ROOT, capture_output=True, text=True)
    d = json.loads(p.stdout)
    by = Counter(); vuln = Counter(); other = Counter()
    for r in d["results"]:
        rule, path = r["check_id"].split(".")[-1], r["path"]
        by[rule] += 1
        (vuln if "exemplars/vulnerable" in path else other)[rule] += 1
    return {"rules": 7, "hits_on_vulnerable_exemplars": dict(sorted(vuln.items())), "hits_elsewhere_in_repo_at_head": dict(sorted(other.items())), "scan_errors": len(d["errors"])}


def build():
    notes = json.loads((ROOT / "docs/incident_notes.json").read_text())
    return {"as_of": ASOF.isoformat(), "supply_chain": supply(), "bounty": bounty(), "audit": audit(), "abuse": abuse(), "review": review(), "incidents": len(notes)}


def markdown(r):
    s, b, a, ab, rv = r["supply_chain"], r["bounty"], r["audit"], r["abuse"], r["review"]
    L = ["# Portcullis report", "", f"As of {r['as_of']}. Generated by `python -m portcullis`; contains no timestamps.", "",
         "## Supply chain", "",
         f"- Real workflows scanned: {s['workflows_scanned']}; findings by severity: {s['workflow_findings_by_severity']}",
         f"- Workflows with no findings: {', '.join(s['workflows_with_no_findings'])}",
         f"- npm registry ECDSA signatures verified: {s['npm_signatures_verified']}; tarball sha512 integrity: {s['npm_tarball_integrity_verified']}",
         f"- Real tarballs with no high or critical findings (known-clean): {s['real_tarballs_with_no_high_findings']}",
         f"- Real packages that run lifecycle scripts (must not be critical): {', '.join(s['real_packages_with_lifecycle_scripts'])}",
         f"- Known compromised versions from real advisories: {', '.join(s['compromised_versions_known'])}", "",
         "## Bug bounty triage (synthetic reports)", "",
         f"- {b['reports']} reports, {b['duplicates']} duplicates; unique by severity: {b['unique_by_severity']}",
         f"- Recurring classes that became rules: {b['recurring_classes']}",
         f"- Prompt-injection reports flagged: {b['injection_flagged']}, severity after decision: {b['injection_severity_after_decision']}",
         f"- Total payout at the rubric's illustrative bands (duplicates pay 0): ${b['total_payout_usd']:,}",
         f"- Fix validation (PoC reproduces, fix blocks it, benign input still works): {b['fix_validation']}", "",
         "## Audit tracker (synthetic engagement)", "", f"- {a}", "",
         "## Anti-scam detection", "",
         f"- Tuned corpus (n={ab['tuned_corpus']['n']}): precision {ab['tuned_corpus']['precision']}, recall {ab['tuned_corpus']['recall']}. Tuned against this set, so treat it as a regression check.",
         f"- Holdout written after tuning (n={ab['holdout']['n']}): precision {ab['holdout']['precision']}, recall {ab['holdout']['recall']}; misses: {ab['holdout']['misses']}",
         f"- Real Sui Move files flagged as drainers: {ab['real_sui_move_files_flagged']}; real npm JS files flagged: {ab['real_npm_js_files_flagged']}", "",
         "## Code review rules (Semgrep)", "",
         f"- {rv['rules']} rules derived from fixed bugs. Hits on vulnerable exemplars: {rv['hits_on_vulnerable_exemplars']}",
         f"- Hits elsewhere at HEAD (should be none): {rv['hits_elsewhere_in_repo_at_head']}; scan errors: {rv['scan_errors']}", "",
         f"## Incidents", "", f"{r['incidents']} incidents with reproduce and fix commits; see docs/incidents.md.", ""]
    return "\n".join(L)


def main():
    r = build()
    (ROOT / "out").mkdir(exist_ok=True)
    (ROOT / "out/report.json").write_text(json.dumps(r, indent=1, sort_keys=True) + "\n")
    (ROOT / "docs/REPORT.md").write_text(markdown(r))
    print(markdown(r))
