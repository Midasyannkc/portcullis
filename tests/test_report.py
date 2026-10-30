import json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(seed):
    env = dict(os.environ, PYTHONHASHSEED=str(seed))
    subprocess.run([sys.executable, "-m", "portcullis"], cwd=ROOT, env=env, check=True, capture_output=True)
    return (ROOT / "out/report.json").read_bytes(), (ROOT / "docs/REPORT.md").read_bytes()


def test_report_is_identical_across_hash_seeds():
    a, b, c = run(1), run(2), run(12345)
    assert a == b == c


def test_report_headline_numbers():
    r = json.loads((ROOT / "out/report.json").read_text())
    assert r["supply_chain"]["npm_signatures_verified"] == "40/40"
    assert r["supply_chain"]["npm_tarball_integrity_verified"] == "10/10"
    assert r["bounty"]["injection_severity_after_decision"] == ["none"]
    assert r["review"]["hits_elsewhere_in_repo_at_head"] == {} and r["review"]["scan_errors"] == 0
    assert r["abuse"]["real_sui_move_files_flagged"] == "0/5"
    assert r["incidents"] == 19
