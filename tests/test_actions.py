import os

from portcullis.supplychain import actions

KEV = actions.kev_actions()
SHA = "a" * 40


def rules(text):
    return {f.rule for f in actions.analyze(text, "w.yml", KEV)}


def wf(trigger="push", steps="", permissions="permissions: {contents: read}\n"):
    return f"name: t\non: {trigger}\n{permissions}jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"


def test_kev_catalog_gives_the_two_known_compromised_actions():
    assert KEV["tj-actions/changed-files"] == "CVE-2025-30066" and "reviewdog/action-setup" in KEV


def test_tag_pinned_kev_action_is_critical():
    fs = actions.analyze(wf(steps="      - uses: tj-actions/changed-files@v45\n"), "w.yml", KEV)
    assert fs[0].severity == "critical" and fs[0].extra["cve"] == "CVE-2025-30066"


def test_sha_pinned_action_is_clean_and_tag_pinned_third_party_is_high():
    assert rules(wf(steps=f"      - uses: some/action@{SHA}\n")) == set()
    f = actions.analyze(wf(steps="      - uses: some/action@v1\n"), "w.yml", KEV)[0]
    assert f.rule == "unpinned-action" and f.severity == "high"


def test_first_party_tag_pin_is_low_and_local_and_docker_digest_are_skipped():
    f = actions.analyze(wf(steps="      - uses: actions/checkout@v4\n"), "w.yml", KEV)[0]
    assert f.severity == "low"
    assert rules(wf(steps="      - uses: ./.github/actions/x\n      - uses: docker://alpine@sha256:abc\n")) == set()


def test_expression_injection_in_run_step():
    steps = '      - run: echo "${{ github.event.issue.title }}"\n'
    assert "expression-injection" in rules(wf("issues", steps))


def test_safe_expression_is_not_flagged():
    assert rules(wf(steps='      - run: echo "${{ github.sha }}"\n')) == set()


def test_missing_permissions_and_write_all():
    assert "no-permissions" in rules(wf(permissions=""))
    assert "write-all" in rules(wf(permissions="permissions: write-all\n"))


def test_secret_echoed_to_log():
    assert "secret-in-log" in rules(wf(steps='      - run: echo "${{ secrets.TOKEN }}"\n'))


def test_real_workflows_are_analyzed_without_error_and_pinned_ones_are_clean():
    out = actions.sweep(os.path.join(actions.ROOT, "data/raw/workflows"), KEV)
    assert len(out) == 13
    for clean in ["expressjs-express-ci.yml", "pallets-flask-tests.yaml", "psf-requests-tests.yml"]:
        assert not [f for f in out[clean] if f.rule == "unpinned-action"], clean
