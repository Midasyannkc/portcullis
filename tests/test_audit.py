from datetime import date
import pytest
from portcullis.audit import Engagement, Finding, TransitionError

D = date(2026, 11, 2)

def test_schedule_skips_weekends_and_holidays():
    e = Engagement("Vendor", ["treasury"], date(2026, 11, 23), 5)
    assert e.fieldwork_end == date(2026, 12, 1)   # Thanksgiving 26th skipped
    assert e.draft_report_due > e.fieldwork_end

def test_happy_path():
    f = Finding("A-1", "x", "high")
    f.move("acknowledged", D); f.move("fix-in-progress", D); f.move("fix-submitted", D, fix_commit="abc")
    f.move("verified-fixed", D, retest_commit="def", retest_passed=True)
    assert f.state == "verified-fixed" and len(f.history) == 4

def test_cannot_skip_to_fixed():
    f = Finding("A-1", "x", "high")
    with pytest.raises(TransitionError):
        f.move("verified-fixed", D, retest_commit="d", retest_passed=True)

def test_failed_retest_blocks_closure():
    f = Finding("A-1", "x", "high")
    f.move("acknowledged", D); f.move("fix-in-progress", D); f.move("fix-submitted", D, fix_commit="abc")
    with pytest.raises(TransitionError):
        f.move("verified-fixed", D, retest_commit="abc", retest_passed=False)
    f.move("fix-in-progress", D)    # sent back
    assert f.state == "fix-in-progress"

def test_high_risk_acceptance_needs_approver():
    f = Finding("A-2", "x", "critical"); f.move("acknowledged", D)
    with pytest.raises(TransitionError):
        f.move("accepted-risk", D)
    f.move("accepted-risk", D, approver="CISO")
    assert f.approver == "CISO"

def test_engagement_closure():
    e = Engagement("V", ["x"], D, 5)
    a, b = Finding("A-1", "x", "low"), Finding("A-2", "y", "low")
    e.findings += [a, b]
    assert not e.can_close()
    for f in (a, b):
        f.move("acknowledged", D); f.move("wont-fix", D)
    assert e.can_close() and e.summary(D)["open"] == 0
