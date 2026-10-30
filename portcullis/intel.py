"""Real advisory intelligence: compromised npm versions (GHSA malware advisories) and RustSec crypto failures."""
import json, re
from pathlib import Path
from portcullis.model import Finding

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw"
MALWARE = re.compile(r"^(?P<name>[@\w./-]+)@(?P<ver>\d[\w.\-]*) contains malware", re.I)


def advisories():
    return [json.loads(p.read_text()) for p in sorted((RAW / "advisories").glob("*.json"))]


def compromised_versions():
    """{(name, version): ghsa_id} from advisories whose summary names a specific malicious version."""
    out = {}
    for a in advisories():
        m = MALWARE.match(a.get("summary", ""))
        if m:
            out[(m["name"], m["ver"])] = a["id"]
    return out


def rustsec():
    out = []
    for p in sorted((RAW / "rustsec").glob("*.md")):
        t = p.read_text()
        g = lambda k: (re.search(rf'^{k} = "?([^"\n]+)"?', t, re.M) or [None, ""])[1]
        cats = re.search(r"categories = \[([^\]]*)\]", t)
        out.append({"id": g("id"), "package": g("package"), "categories": re.findall(r'"([^"]+)"', cats[1]) if cats else []})
    return out


def check_lock(lock, bad=None):
    bad = bad or compromised_versions()
    out = []
    for key, p in (lock.get("packages") or {}).items():
        name = key.split("node_modules/")[-1]
        hit = bad.get((name, p.get("version", "")))
        if hit:
            out.append(Finding("intel", "compromised-version", "critical", f"{name}@{p['version']} is a known malicious release", f"package-lock.json:{name}",
                               "supply-chain", f"advisory {hit}"))
    return out
