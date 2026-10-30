import json, os, time, copy
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from portcullis.supplychain import lockfile, provenance as pv

def lock(**over):
    p = {"node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-xx"}}
    p["node_modules/a"].update(over)
    return {"packages": {"": {}, **p}}

def test_lock_clean():
    assert lockfile.analyze(lock()) == []

@pytest.mark.parametrize("over,rule", [
    ({"resolved": "http://registry.npmjs.org/a/-/a-1.0.0.tgz"}, "insecure-resolved"),
    ({"resolved": "git+ssh://git@github.com/x/a.git#abc"}, "git-dependency"),
    ({"resolved": "https://evil.example/a.tgz"}, "foreign-registry"),
    ({"integrity": ""}, "missing-integrity"),
    ({"integrity": "sha1-abc"}, "weak-integrity"),
])
def test_lock_flags(over, rule):
    assert rule in {f.rule for f in lockfile.analyze(lock(**over))}

def test_lock_diff_integrity_swap():
    new = lock(integrity="sha512-yy")
    assert [f.rule for f in lockfile.diff(lock(), new)] == ["integrity-changed-same-version"]
    assert lockfile.diff(lock(), lock(version="1.0.1", integrity="sha512-yy")) == []

@pytest.fixture
def tree(tmp_path):
    (tmp_path / "src").mkdir(); (tmp_path / "src/a.js").write_text("a"); (tmp_path / "b.txt").write_text("b")
    return tmp_path

def test_tar_is_reproducible(tree):
    t1 = pv.deterministic_tar(tree)
    os.utime(tree / "b.txt", (time.time() + 999, time.time() + 999))
    assert pv.deterministic_tar(tree) == t1

def test_tar_changes_with_content(tree):
    t1 = pv.deterministic_tar(tree); (tree / "b.txt").write_text("c")
    assert pv.deterministic_tar(tree) != t1

def mk(art, pinned=True):
    k = Ed25519PrivateKey.generate()
    st = pv.statement("pkg.tgz", art, "https://github.com/actions/runner", "git+https://example/org/repo", "abc123", ".github/workflows/release.yml", pinned)
    return k, pv.sign(st, k, "k1")

POL = dict(allowed_builders={"https://github.com/actions/runner"}, allowed_sources={"git+https://example/org/repo"})

def test_provenance_accepts_good(tree):
    art = pv.deterministic_tar(tree); k, env = mk(art)
    assert pv.check_policy(env, art, k.public_key(), "k1", expected_commit="abc123", **POL) == []

def test_provenance_rejects_swapped_artifact(tree):
    art = pv.deterministic_tar(tree); k, env = mk(art)
    assert "artifact digest does not match attested subject" in pv.check_policy(env, art + b"x", k.public_key(), "k1", **POL)

def test_provenance_rejects_tampered_statement(tree):
    art = pv.deterministic_tar(tree); k, env = mk(art)
    st = json.loads(__import__("base64").b64decode(env["payload"])); st["predicate"]["runDetails"]["builder"]["id"] = "evil"
    env["payload"] = __import__("base64").b64encode(pv._canon(st)).decode()
    assert pv.check_policy(env, art, k.public_key(), "k1", **POL) == ["signature invalid or key unknown"]

def test_provenance_rejects_wrong_key_and_policy(tree):
    art = pv.deterministic_tar(tree); k, env = mk(art, pinned=False)
    assert pv.check_policy(env, art, Ed25519PrivateKey.generate().public_key(), "k1", **POL)
    v = pv.check_policy(env, art, k.public_key(), "k1", expected_commit="zzz", **POL)
    assert "build used unpinned actions" in v and "commit differs from the reviewed commit" in v


from portcullis import intel


def test_real_advisories_yield_compromised_versions():
    bad = intel.compromised_versions()
    assert bad[("debug", "4.4.2")] == "GHSA-4x49-vf9v-38px"
    assert ("backslash", "0.2.1") in bad and ("color-name", "2.0.1") in bad


def test_lock_with_compromised_debug_is_flagged_and_real_fixed_version_is_not():
    mk = lambda v: {"packages": {"": {}, "node_modules/debug": {"version": v}}}
    assert [f.rule for f in intel.check_lock(mk("4.4.2"))] == ["compromised-version"]
    assert intel.check_lock(mk("4.4.3")) == []     # 4.4.3 is the real release in data/raw/npm/tarballs


def test_rustsec_includes_the_mysten_related_ed25519_advisory():
    r = {a["id"]: a for a in intel.rustsec()}
    assert r["RUSTSEC-2022-0093"]["package"] == "ed25519-dalek" and "crypto-failure" in r["RUSTSEC-2022-0093"]["categories"]
