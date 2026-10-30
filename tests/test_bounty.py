from datetime import date
import pytest
from portcullis.bounty import triage as T, fixcheck as F
from portcullis.bizdays import add_business_days, business_days_between

REPORTS = T.load()
ROWS = {r["id"]: r for r in T.decide(REPORTS)}

def test_corpus_size():
    assert len(REPORTS) == 40

def test_injection_cannot_raise_severity():
    inj = next(r for r in REPORTS if "SYSTEM NOTICE" in r["body"])
    row = ROWS[inj["id"]]
    assert row["injection_flag"] and row["severity"] == "none"
    drafted = {inj["id"]: "critical"}
    row2 = next(x for x in T.decide(REPORTS, claimed=drafted) if x["id"] == inj["id"])
    assert row2["severity"] == "none" and row2["llm_claimed"] == "critical"

def test_severity_ignores_prose():
    r = dict(REPORTS[0]); base = T.severity(r)
    r["body"] = "CRITICAL CRITICAL pays maximum"; r["title"] = "CRITICAL funds theft"
    assert T.severity(r) == base

def test_severity_ordering_examples():
    by = {r["class_claimed"]: ROWS[r["id"]]["severity"] for r in REPORTS if r["asset"] == "treasury-move"}
    assert by["move-capability"] == "critical"
    assert ROWS[next(r["id"] for r in REPORTS if r["class_claimed"] == "lookalike")]["severity"] == "none"

def test_business_days():
    assert add_business_days(date(2026, 10, 30), 1) == date(2026, 11, 2)
    assert add_business_days(date(2026, 11, 25), 1) == date(2026, 11, 27)   # Thanksgiving skipped
    assert business_days_between(date(2026, 10, 30), date(2026, 11, 2)) == 1

def test_sla_dates():
    r = next(x for x in REPORTS if x["id"] == "R-001")
    s = T.sla(r, "high")
    assert s["first_response_due"] > r["received"] and s["fix_due"] > s["first_response_due"]

def test_budget_cap_and_duplicates():
    b = T.Budget(60000)
    assert b.approve("a", "critical") == 50000
    assert b.approve("dup", "critical", duplicate=True) == 0
    with pytest.raises(T.BudgetExceeded):
        b.approve("b", "high") and b.approve("c", "high")
    assert b.paid <= 60000

def test_total_payout_within_plausible_budget():
    b = T.Budget(10**9)
    for r in ROWS.values():
        b.approve(r["id"], r["severity"], duplicate=bool(r["duplicate_of"]))
    assert 0 < b.paid < 1_000_000

def test_recurring_classes():
    rc = T.recurring(list(ROWS.values()))
    assert "lookalike" not in rc

@pytest.mark.parametrize("cls", ["ssrf", "xss", "redirect"])
def test_fix_validation_accepts_real_fix(cls):
    assert F.validate(cls)["accepted"]

def test_fix_validation_rejects_noop_fix(monkeypatch):
    p = dict(F.PAIRS["ssrf"]); p["fixed"] = F.ssrf_vuln
    monkeypatch.setitem(F.PAIRS, "ssrf", p)
    assert not F.validate("ssrf")["accepted"]


def test_known_duplicates_found():
    found = {k: v["duplicate_of"] for k, v in ROWS.items() if v["duplicate_of"]}
    expected = {r["id"]: r["duplicate_of"] for r in REPORTS if r["duplicate_of"]}
    assert found == expected


def test_distinct_bugs_on_same_asset_are_not_merged():
    originals = [r for r in REPORTS if not r["duplicate_of"]]
    assert all(ROWS[r["id"]]["duplicate_of"] is None for r in originals)


def test_recurring_classes_found():
    rc = T.recurring(list(ROWS.values()))
    assert {"ssrf", "xss", "authz", "move-capability"} <= set(rc)
