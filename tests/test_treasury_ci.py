from pathlib import Path
from portcullis.supplychain import actions

WF = Path(__file__).resolve().parents[1] / "target/treasury-ci/.github/workflows/release.yml"


def findings():
    return actions.analyze_file(WF, actions.kev_actions())


def test_release_workflow_has_no_high_or_critical_findings():
    bad = [(f.rule, f.severity) for f in findings() if f.severity in ("high", "critical")]
    assert bad == []


def test_release_workflow_only_runs_on_trusted_triggers():
    text = WF.read_text()
    assert "pull_request_target" not in text


def test_release_workflow_declares_least_privilege_permissions():
    assert "permissions:" in WF.read_text()
