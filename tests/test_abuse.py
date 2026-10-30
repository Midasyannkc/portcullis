import json, tarfile, io
from pathlib import Path
from portcullis.abuse import detect as D

RAW = Path(__file__).resolve().parents[1] / "data/raw"
CORPUS = [tuple(s) for s in json.loads((Path(__file__).resolve().parents[1] / "data/synthetic/abuse_corpus.json").read_text())]


def test_corpus_has_both_labels():
    assert len(CORPUS) == 91 and sum(1 for c in CORPUS if c[2]) == 42


def test_aggregate_quality_floor():
    e = D.evaluate(CORPUS)
    assert e["precision"] >= 0.9 and e["recall"] >= 0.75, e


def test_real_sui_move_has_no_drainer_findings():
    files = list((RAW / "move").glob("*.move"))
    assert len(files) == 5
    for f in files:
        assert D.move_score(f.read_text())[0] < 4, f.name


def test_real_npm_javascript_has_no_drainer_findings():
    n = 0
    for t in (RAW / "npm/tarballs").glob("*.tgz"):
        with tarfile.open(t) as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith((".js", ".mjs", ".cjs")):
                    n += 1
                    assert D.js_score(tf.extractfile(m).read().decode("utf8", "ignore"))[0] < 4, (t.name, m.name)
    assert n >= 20


def test_exact_and_subdomain_of_legit_domains_are_clean():
    for d in ("sui.io", "docs.sui.io", "blog.mystenlabs.com"):
        assert D.domain_score(d)[0] == 0


def test_brand_in_subdomain_of_unrelated_domain_is_flagged():
    for d in ("sui.airdrop-claim.xyz", "mystenlabs.verify-wallet.top", "walrus.reward-claim.live", "suiexplorer.recover-wallet.xyz"):
        assert D.domain_is_phish(d)[0], d


def test_digit_one_can_stand_for_i_or_l():
    assert D.domain_is_phish("su1-rewards.xyz")[0]
    assert D.domain_is_phish("mysten1abs-support.link")[0]


def test_single_strong_drainer_signals_reach_threshold():
    for src in ("await token.approve(spender, MaxUint256);await nft.setApprovalForAll(attacker, true);",
                "ethereum.request({method:'eth_sign',params:[addr,'0x" + "11" * 32 + "']})",
                "wallet.signAndExecuteTransaction({tx}); const message='verify your wallet to claim airdrop'",
                "const MAX=2**256-1; erc20.approve(drain, MAX_UINT)"):
        assert D.verdict("js", src)[0], src


def test_typo_only_and_marketing_phrases_are_not_enough():
    assert not D.domain_is_phish("waltrus-electric.com")[0]
    assert not D.verdict("page", '<title>Newsletter</title><form action="https://list.example/subscribe"><input name="email"></form><p>Limited time: 20% off swag</p>')[0]
    assert D.verdict("page", '<title>Claim your SUI airdrop</title><p>Act now, limited time.</p><form><input name="mnemonic" placeholder="secret recovery phrase"></form>')[0]


def test_corpus_has_no_false_positives_and_few_misses():
    e = D.evaluate(CORPUS)
    assert e["fp"] == 0 and e["fn"] <= 1, e["misses"]


def test_holdout_written_after_tuning():
    """Samples written after the detectors were tuned.  One known miss: sulwalet.xyz (two edits at once)."""
    hold = [tuple(s) for s in json.loads((Path(__file__).resolve().parents[1] / "data/synthetic/abuse_holdout.json").read_text())]
    e = D.evaluate(hold)
    assert e["precision"] == 1.0 and e["recall"] >= 0.9
    assert [m[2] for m in e["misses"]] == ["sulwalet.xyz"]
