"""For every incident, check out its reproduce and fix commits in scratch worktrees and run the test
files the reproduce commit touched (pytest, cargo or node, by path).  Reproduce must fail, fix must pass."""
import json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sh = lambda *a, cwd=ROOT: subprocess.run(a, cwd=cwd, capture_output=True, text=True)
log = [l.split("|", 1) for l in sh("git", "log", "--reverse", "--format=%h|%s").stdout.strip().splitlines()]
notes = json.load(open(os.path.join(ROOT, "docs/incident_notes.json")))
only = set(map(int, sys.argv[1:]))
commit_for = lambda n, k: next(h for h, s in log if s.startswith(f"INC-{n} {k}:"))


def run_at(sha, files):
    with tempfile.TemporaryDirectory() as td:
        wt = os.path.join(td, "wt")
        sh("git", "worktree", "add", "--detach", wt, sha)
        rc, last = 0, ""
        py = [f for f in files if f.startswith("tests/test_")]
        if py:
            p = sh(sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *py, cwd=wt); rc |= p.returncode
            last = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr[-120:]
        if any(f.startswith("target/treasury-rs/") for f in files):
            p = sh("cargo", "test", "--offline", "--test", "exploits", cwd=os.path.join(wt, "target/treasury-rs")); rc |= p.returncode
            last = next((l for l in p.stdout.splitlines() if "test result" in l and "0 passed; 0 failed" not in l), last or "cargo")
        if any(f.startswith("target/treasury-ts/") for f in files):
            p = sh("node", "--test", "test/exploits.test.ts", cwd=os.path.join(wt, "target/treasury-ts")); rc |= p.returncode
            last = "node " + next((l for l in p.stdout.splitlines() if l.startswith("# pass") or l.startswith("# fail")), "")
        sh("git", "worktree", "remove", "--force", wt)
        return rc, last


bad = 0
for x in notes:
    n = x["n"]
    if only and n not in only:
        continue
    r, f = commit_for(n, "reproduce"), commit_for(n, "fix")
    files = [p for p in sh("git", "show", "--name-only", "--format=", r).stdout.split() if "test" in p]
    rc1, o1 = run_at(r, files); rc2, o2 = run_at(f, files)
    ok = rc1 != 0 and rc2 == 0
    bad += not ok
    print(f"INC-{n:<2} {'OK ' if ok else 'BAD'} reproduce[{r}]: {o1} | fix[{f}]: {o2}", flush=True)
sys.exit(1 if bad else 0)
