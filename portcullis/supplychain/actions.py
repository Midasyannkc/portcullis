"""Static analysis of GitHub Actions workflows: the CI/CD half of software supply chain security.

Classes covered: unpinned third-party actions (the tj-actions/changed-files and reviewdog compromises
rewrote tags, so a tag is not a pin), expression injection into run steps, pull_request_target
"pwn request" checkouts, over-broad GITHUB_TOKEN permissions, and secrets written to logs."""
from __future__ import annotations

import json
import os
import re

import yaml

from ..model import Finding

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHA = re.compile(r"^[0-9a-f]{40}$")
FIRST_PARTY = {"actions", "github"}
UNTRUSTED = [
    r"github\.event\.issue\.(title|body)",
    r"github\.event\.pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.pages\.[^.]*\.page_name",
    r"github\.event\.commits\.[^.]*\.(message|author\.(email|name))",
    r"github\.event\.head_commit\.(message|author\.(email|name))",
    r"github\.head_ref",
]
EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.S)


def kev_actions(kev_path=None) -> dict:
    """Map 'owner/repo' to the KEV entry for every GitHub Action in CISA's catalog."""
    kev_path = kev_path or os.path.join(ROOT, "data/raw/kev.json")
    out = {}
    for v in json.load(open(kev_path))["vulnerabilities"]:
        if v["product"].endswith("GitHub Action"):
            name = v["product"][: -len(" GitHub Action")].strip().replace(" ", "-")
            out[f"{v['vendorProject']}/{name}".lower()] = v["cveID"]
    return out


def steps_of(wf: dict):
    for job_id, job in (wf.get("jobs") or {}).items():
        for i, step in enumerate(job.get("steps") or []):
            yield job_id, i, job, step


def analyze(text: str, path: str, kev: dict | None = None) -> list[Finding]:
    kev = kev if kev is not None else kev_actions()
    wf = yaml.safe_load(text) or {}
    out: list[Finding] = []
    triggers = wf.get("on")
    names = set(triggers if isinstance(triggers, (list, dict)) else [triggers])

    # permissions
    top = wf.get("permissions")
    if top is None and not any("permissions" in (j or {}) for j in (wf.get("jobs") or {}).values()):
        out.append(Finding("actions", "no-permissions", "medium", "workflow does not restrict GITHUB_TOKEN permissions", path, "token-permissions"))
    if top == "write-all":
        out.append(Finding("actions", "write-all", "high", "workflow grants write-all to GITHUB_TOKEN", path, "token-permissions", "write-all"))

    for job_id, i, job, step in steps_of(wf):
        loc = f"{path}#{job_id}.steps[{i}]"
        uses = step.get("uses")
        if uses and not uses.startswith("./") and not uses.startswith("docker://"):
            repo, _, ref = uses.partition("@")
            owner = repo.split("/")[0]
            if not SHA.match(ref):
                key = "/".join(repo.split("/")[:2]).lower()
                if key in kev:
                    out.append(Finding("actions", "kev-action-unpinned", "critical", f"{repo}@{ref} is in CISA KEV ({kev[key]}) and is not pinned to a commit", loc, "unpinned-action", repo,
                                       {"cve": kev[key]}))
                else:
                    sev = "low" if owner in FIRST_PARTY else "high"
                    out.append(Finding("actions", "unpinned-action", sev, f"{repo}@{ref} is not pinned to a commit SHA", loc, "unpinned-action", repo))
        for field_name in ("run",):
            body = step.get(field_name)
            if isinstance(body, str):
                for m in EXPR.finditer(body):
                    inner = m.group(1).strip()
                    if any(re.search(p, inner) for p in UNTRUSTED):
                        out.append(Finding("actions", "expression-injection", "high", f"untrusted input {inner} is expanded into a shell command", loc, "expression-injection", inner))
                    if inner.startswith("secrets.") and re.search(r"\becho\b|\bprintf\b", body):
                        out.append(Finding("actions", "secret-in-log", "high", f"{inner} is written by a shell command and can reach logs", loc, "secret-exposure", inner))
        if uses and uses.startswith("actions/checkout") and "pull_request_target" in names:
            ref = str((step.get("with") or {}).get("ref", ""))
            if "github.event.pull_request.head" in ref or "github.head_ref" in ref:
                out.append(Finding("actions", "pwn-request", "critical", "pull_request_target checks out untrusted pull request code with a privileged token", loc, "pwn-request", ref))
    return out


def analyze_file(path: str, kev=None) -> list[Finding]:
    rel = os.path.relpath(path, ROOT)
    return analyze(open(path).read(), rel, kev)


def sweep(directory: str, kev=None) -> dict[str, list[Finding]]:
    kev = kev if kev is not None else kev_actions()
    out = {}
    for fn in sorted(os.listdir(directory)):
        if fn.endswith((".yml", ".yaml")):
            out[fn] = analyze_file(os.path.join(directory, fn), kev)
    return out
