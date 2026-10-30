"""External audit engagement tracker: schedule, findings state machine, retest-gated closure."""
from dataclasses import dataclass, field
from datetime import date
from portcullis.bizdays import add_business_days, business_days_between

STATES = ["reported", "acknowledged", "fix-in-progress", "fix-submitted", "verified-fixed", "accepted-risk", "wont-fix"]
ALLOWED = {
    "reported": {"acknowledged"},
    "acknowledged": {"fix-in-progress", "accepted-risk", "wont-fix"},
    "fix-in-progress": {"fix-submitted"},
    "fix-submitted": {"verified-fixed", "fix-in-progress"},   # retest fails -> back to work
    "verified-fixed": set(), "accepted-risk": set(), "wont-fix": set(),
}
TERMINAL = {"verified-fixed", "accepted-risk", "wont-fix"}


class TransitionError(Exception):
    pass


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    state: str = "reported"
    history: list = field(default_factory=list)
    fix_commit: str = ""
    retest_commit: str = ""
    approver: str = ""

    def move(self, to, on: date, **kw):
        if to not in ALLOWED[self.state]:
            raise TransitionError(f"{self.id}: {self.state} -> {to} not allowed")
        if to == "verified-fixed":
            if not (self.fix_commit and kw.get("retest_commit")):
                raise TransitionError(f"{self.id}: verified-fixed needs a fix commit and a retest commit")
            if kw["retest_commit"] == self.fix_commit and not kw.get("retest_passed"):
                raise TransitionError(f"{self.id}: retest did not pass")
            if not kw.get("retest_passed"):
                raise TransitionError(f"{self.id}: retest did not pass")
            self.retest_commit = kw["retest_commit"]
        if to == "fix-submitted":
            self.fix_commit = kw.get("fix_commit", "")
            if not self.fix_commit:
                raise TransitionError(f"{self.id}: fix-submitted needs a fix commit")
        if to in ("accepted-risk", "wont-fix"):
            if self.severity in ("critical", "high") and not kw.get("approver"):
                raise TransitionError(f"{self.id}: {to} for {self.severity} needs a named approver")
            self.approver = kw.get("approver", "")
        self.history.append((on.isoformat(), self.state, to))
        self.state = to


@dataclass
class Engagement:
    vendor: str
    scope: list
    kickoff: date
    fieldwork_days: int
    report_days: int = 5
    findings: list = field(default_factory=list)

    @property
    def fieldwork_end(self): return add_business_days(self.kickoff, self.fieldwork_days)
    @property
    def draft_report_due(self): return add_business_days(self.fieldwork_end, self.report_days)
    @property
    def retest_window(self): return (self.draft_report_due, add_business_days(self.draft_report_due, 15))

    def open_findings(self): return [f for f in self.findings if f.state not in TERMINAL]

    def can_close(self):
        """Engagement closes only when nothing is open and every critical/high is verified-fixed or explicitly approved."""
        return not self.open_findings()

    def summary(self, today: date):
        c = {}
        for f in self.findings:
            c[f.state] = c.get(f.state, 0) + 1
        return {"vendor": self.vendor, "fieldwork_end": self.fieldwork_end.isoformat(), "draft_report_due": self.draft_report_due.isoformat(),
                "retest_window": [d.isoformat() for d in self.retest_window], "states": dict(sorted(c.items())),
                "open": len(self.open_findings()), "business_days_to_retest_close": business_days_between(today, self.retest_window[1]),
                "can_close": self.can_close()}
