"""Bug bounty triage. Severity is decided from structured facts only.

Report prose is untrusted input: it is never parsed for severity, payout or
instructions.  An LLM may draft a response from the prose, but this module
has the final say on severity (see ``decide``)."""
import json, re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from portcullis.bizdays import add_business_days

ROOT = Path(__file__).resolve().parents[2]
SEV_ORDER = ["none", "low", "medium", "high", "critical"]
IMPACT_PTS = {"funds": 6, "account-takeover": 5, "credential": 5, "user-session": 4, "user-data": 4, "internal-network": 4,
              "availability": 3, "phishing-aid": 1, "third-party": 0, "none": 0}
TIER_PTS = {"critical": 2, "high": 1, "standard": 0, "out-of-scope": -99}
CX_PTS = {"low": 2, "medium": 1, "high": 0}
PRIV_PTS = {"none": 1, "low": 0, "high": -1}
SLA_BDAYS = {"critical": (1, 7), "high": (2, 30), "medium": (3, 60), "low": (5, 90), "none": (5, 5)}  # (first response, target fix)
BANDS = {"critical": 50000, "high": 15000, "medium": 3000, "low": 500, "none": 0}

INJECTION = re.compile(r"(ignore (all )?(previous|prior) instructions|system notice|you are now|classify this (report )?as|approve the maximum|do not mention)", re.I)


def load(path=None):
    return json.loads(Path(path or ROOT / "data/synthetic/bounty_reports.json").read_text())


def injection_flag(r):
    return bool(INJECTION.search(r["title"] + " " + r["body"]))


def severity(r) -> str:
    """Deterministic rubric over structured fields.  Reads no free text."""
    if r["tier"] == "out-of-scope" or IMPACT_PTS.get(r["impact"], 0) == 0:
        return "none"
    s = IMPACT_PTS[r["impact"]] + TIER_PTS[r["tier"]] + CX_PTS[r["complexity"]] + PRIV_PTS[r["privileges"]]
    return "critical" if s >= 10 else "high" if s >= 8 else "medium" if s >= 6 else "low" if s >= 3 else "none"


_STOP = {"in", "the", "of", "a", "an", "on", "to", "affecting", "and"}


def _tokens(t):
    return {w for w in re.findall(r"[a-z0-9]+", t.lower()) if w not in _STOP}


def dedupe(reports):
    """Map each report id to the id of the earliest report on the same asset and class with similar title."""
    seen, out = [], {}
    for r in sorted(reports, key=lambda x: (x["received"], x["id"])):
        match = None
        for s in seen:
            if s["asset"] == r["asset"] and s["class_claimed"] == r["class_claimed"]:
                a, b = _tokens(s["title"]), _tokens(r["title"])
                if len(a & b) / len(a | b) >= 0.6:
                    match = s["id"]; break
        out[r["id"]] = match
        if match is None:
            seen.append(r)
    return out


def sla(r, sev):
    rd = date.fromisoformat(r["received"])
    first, fix = SLA_BDAYS[sev]
    return {"first_response_due": add_business_days(rd, first).isoformat(), "fix_due": add_business_days(rd, fix).isoformat()}


class BudgetExceeded(Exception):
    pass


class Budget:
    def __init__(self, cap):
        self.cap, self.paid, self.ledger = cap, 0, []

    def approve(self, rid, sev, duplicate=False):
        amt = 0 if duplicate else BANDS[sev]
        if self.paid + amt > self.cap:
            raise BudgetExceeded(f"{rid}: {amt} would exceed cap {self.cap} (paid {self.paid})")
        self.paid += amt
        self.ledger.append((rid, sev, amt))
        return amt


def decide(reports, claimed=None):
    """claimed: optional {id: severity} from an LLM draft; it is recorded but never used."""
    dups = dedupe(reports)
    rows = []
    for r in sorted(reports, key=lambda x: x["id"]):
        sev = severity(r)
        rows.append({"id": r["id"], "class": r["class_claimed"], "asset": r["asset"], "severity": sev, "duplicate_of": dups[r["id"]],
                     "injection_flag": injection_flag(r), "llm_claimed": (claimed or {}).get(r["id"]), **sla(r, sev)})
    return rows


def recurring(rows, min_count=3):
    from collections import Counter
    c = Counter(r["class"] for r in rows if r["duplicate_of"] is None and r["severity"] != "none")
    return {k: v for k, v in sorted(c.items()) if v >= min_count}
