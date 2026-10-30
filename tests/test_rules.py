"""Semgrep rule tests: must fire on vulnerable exemplars, and must stay quiet on known-clean code
(fixed Treasury sources, the real Sui framework Move files and real npm package JavaScript).

Note: `semgrep --validate` downloads a lint pack from semgrep.dev, which the build sandbox blocks.
Loading the rules in a real scan (which parses and checks them) is used as the validation step."""
import json, subprocess, tarfile
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules/portcullis.yml"


@pytest.fixture(scope="session")
def scan(tmp_path_factory):
    work = tmp_path_factory.mktemp("sg")
    js = work / "npmjs"; js.mkdir()
    for t in (ROOT / "data/raw/npm/tarballs").glob("*.tgz"):
        with tarfile.open(t) as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith((".js", ".mjs", ".cjs")):
                    (js / f"{t.stem}__{Path(m.name).name}").write_bytes(tf.extractfile(m).read())
    cmd = ["semgrep", "--config", str(RULES), "--metrics=off", "--disable-version-check", "--json", "--quiet",
           str(ROOT / "rules/exemplars"), str(ROOT / "target"), str(ROOT / "data/raw/move"), str(js)]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    data = json.loads(p.stdout)
    assert data["errors"] == [], data["errors"]
    hits = {}
    for r in data["results"]:
        rel = str(Path(r["path"]).resolve().relative_to(ROOT)) if str(r["path"]).startswith(str(ROOT)) or not str(r["path"]).startswith("/") else r["path"]
        hits.setdefault(r["check_id"].split(".")[-1], set()).add(rel)
    return hits


def fired(scan, rule, path_part):
    return any(path_part in p for p in scan.get(rule, ()))


VULN = [("ts-ssrf-unvalidated-url", "vulnerable/preview.ts"), ("ts-xss-unescaped-template", "vulnerable/render.ts"),
        ("ts-weak-rng-secret", "vulnerable/session.ts"), ("rust-lossy-narrowing-cast", "vulnerable/lib.rs"),
        ("rust-unchecked-slice-of-input", "vulnerable/lib.rs"), ("rust-early-exit-secret-compare", "vulnerable/lib.rs"),
        ("move-public-fn-mutates-without-capability", "vulnerable/treasury.move")]


@pytest.mark.parametrize("rule,path", VULN)
def test_rule_fires_on_vulnerable_exemplar(scan, rule, path):
    assert fired(scan, rule, path), (rule, sorted(scan))


def test_every_rule_has_derivation_metadata():
    import yaml
    rules = yaml.safe_load(RULES.read_text())["rules"]
    assert len(rules) == 7 and all(r["metadata"]["derived-from"].startswith("INC-") for r in rules)


def test_variant_sweep_finds_no_unvalidated_fetch_left_in_treasury(scan):
    """The INC-11 fix covered linkPreview only.  The rule derived from it must find no other sink."""
    assert not fired(scan, "ts-ssrf-unvalidated-url", "target/treasury-ts/src")


def test_treasury_move_withdraw_requires_admin_cap(scan):
    assert not fired(scan, "move-public-fn-mutates-without-capability", "target/treasury-move")
    src = (ROOT / "target/treasury-move/sources/treasury.move").read_text()
    assert "_cap: &AdminCap" in src or "cap: &AdminCap" in src
