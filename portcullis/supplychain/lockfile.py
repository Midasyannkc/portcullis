"""package-lock.json (v2/v3) analysis."""
import json
from portcullis.model import Finding

REGISTRY = "https://registry.npmjs.org/"


def analyze(lock: dict, path="package-lock.json"):
    out = []
    for key, p in (lock.get("packages") or {}).items():
        if not key:
            continue
        name = key.split("node_modules/")[-1]
        loc = f"{path}:{name}"
        res = p.get("resolved", "")
        if p.get("link"):
            continue
        if res.startswith("http://"):
            out.append(Finding("lockfile", "insecure-resolved", "high", "Package resolved over plain HTTP", loc, "supply-chain", res))
        elif res.startswith(("git+", "git:", "github:")) or "github.com" in res:
            out.append(Finding("lockfile", "git-dependency", "high", "Dependency resolved from a git URL, not the registry", loc, "supply-chain", res))
        elif res and not res.startswith(REGISTRY):
            out.append(Finding("lockfile", "foreign-registry", "high", "Package resolved from a non-default registry host", loc, "supply-chain", res))
        if res and not p.get("integrity"):
            out.append(Finding("lockfile", "missing-integrity", "high", "Locked package has no integrity hash", loc, "supply-chain", res))
        elif p.get("integrity", "").startswith("sha1-"):
            out.append(Finding("lockfile", "weak-integrity", "medium", "sha1 integrity only", loc, "crypto-failure", p["integrity"]))
        if p.get("hasInstallScript") and not p.get("dev"):
            out.append(Finding("lockfile", "install-script-dep", "low", "Production dependency runs an install script", loc, "supply-chain", "hasInstallScript"))
    return out


def diff(old: dict, new: dict):
    """Flag resolved-host or integrity changes where the version did not change."""
    out = []
    op, np_ = old.get("packages", {}), new.get("packages", {})
    for k, n in np_.items():
        o = op.get(k)
        if not o or not k:
            continue
        if o.get("version") == n.get("version") and o.get("integrity") != n.get("integrity"):
            out.append(Finding("lockfile", "integrity-changed-same-version", "critical", "Integrity changed without a version bump", f"{k}", "supply-chain",
                               f"{o.get('integrity')} -> {n.get('integrity')}"))
    return out
