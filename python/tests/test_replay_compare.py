"""Replay and compare: verified timelines, tampering, agreement, errors, no writes, upload shape."""

import json

import pytest

import signafaide
from signafaide import cli, runtime
from signafaide.crypto import hash_json
from signafaide.experiments import VerificationFailed
from helpers import chain_path, records


@pytest.fixture
def payouts(recorder):
    @signafaide.record(name="approve_payout")
    def approve_payout(claim_id: str, amount: int):
        return {"approved": amount < 500}

    for i in range(10):
        approve_payout(f"c-{i}", i * 100)
    signafaide.note("shift_end", {"by": "ops"})
    assert recorder.flush()["left"] == 0
    return approve_payout


def snapshot(rec):
    path = chain_path(rec)
    return path.read_bytes(), sorted(p.name for p in (rec.state.home / "outbox").rglob("*.json"))


def test_replay_shows_verified_inputs_and_outputs(payouts, recorder, tmp_path):
    r = signafaide.replay()
    assert r.ok and len(r.entries) == r.total == 21
    d, o = r.entries[0], r.entries[1]
    assert d.status == o.status == "verified"
    assert d.content["input"] == {"claim_id": "c-0", "amount": 0} and o.content == {"output": {"approved": True}}
    assert d.pair is o and o.pair is d
    text = str(r)
    assert "approve_payout  -> outcome #2" in text and '"claim_id": "c-0"' in text and text.endswith("each checked against its content_hash, its signature and its receipt")
    page = r.to_html()
    assert "<script" not in page and "<link" not in page and "src=" not in page
    assert "c-9" in page and "verified" in page
    # One record and its outcome.
    one = signafaide.replay(record=o.hash[:10])
    assert [e.envelope["seq"] for e in one.entries] == [1, 2]


def test_replay_catches_tampered_content(payouts, recorder):
    lines = chain_path(recorder).read_text().splitlines()
    rec = json.loads(lines[4])
    rec["content"]["input"]["amount"] = 1  # the agent saw 200
    lines[4] = json.dumps(rec)
    chain_path(recorder).write_text("\n".join(lines) + "\n")
    r = signafaide.replay()
    assert not r.ok and r.report.first_failed() == "content"
    bad = [e for e in r.entries if e.problems]
    assert [e.envelope["seq"] for e in bad] == [5] and bad[0].status == "FAIL"
    assert "content hashes to" in bad[0].problems[0]
    with pytest.raises(VerificationFailed):
        signafaide.compare(lambda claim_id, amount: {"approved": True})


def test_compare_agreement_changes_and_errors(payouts, recorder):
    before = snapshot(recorder)

    def stricter(claim_id, amount):
        if claim_id == "c-9":
            raise RuntimeError("model timeout")
        return {"approved": amount < 300}

    rep = signafaide.compare(stricter, name="approve_payout")
    assert (rep.n, rep.agreed, rep.changed, rep.errors) == (10, 7, 2, 1)
    changed = [r for r in rep.rows if r.result == "changed"]
    assert [r.input["claim_id"] for r in changed] == ["c-3", "c-4"]
    assert changed[0].recorded == {"approved": True} and changed[0].candidate == {"approved": False}
    err = [r for r in rep.rows if r.result == "error"][0]
    assert err.same is None and err.error == "RuntimeError: model timeout"
    # A custom comparison and a limit.
    loose = signafaide.compare(lambda claim_id, amount: {"approved": "yes"}, same=lambda a, b: bool(a["approved"]) == bool(b["approved"]), limit=3)
    assert (loose.n, loose.agreed, loose.changed) == (3, 0, 3)  # c-7..c-9 were refused
    assert snapshot(recorder) == before


def test_compare_never_writes_records_even_through_recorded_tools(payouts, recorder):
    before = snapshot(recorder)
    ran = []

    @signafaide.record(name="send_money")
    def send_money(amount):
        ran.append(amount)

    def candidate(claim_id, amount):
        send_money(amount)  # a real side effect: refused before it runs
        return {"approved": True}

    rep = signafaide.compare(candidate)
    assert rep.errors == rep.n == 10 and ran == []
    assert "must be side-effect free" in rep.rows[0].error
    assert snapshot(recorder) == before
    payouts("c-new", 1)  # recording works again afterwards
    assert len(records(recorder)) == 23


def test_upload_payload_is_hash_only_by_default(payouts, recorder, service):
    rep = signafaide.compare(lambda claim_id, amount: {"approved": amount < 300}, name="approve_payout", label="v2 threshold")
    body = rep.payload()
    assert set(body) == {"agent", "name", "label", "candidate", "rows"} and body["agent"] == "claims-project"
    row = body["rows"][3]
    assert set(row) == {"record_hash", "outcome_hash", "result", "candidate_hash"}
    assert row["result"] == "changed" and row["candidate_hash"] == hash_json({"approved": False})
    full = rep.payload(values=True)["rows"][3]
    assert full["recorded"] == {"approved": True} and full["candidate"] == {"approved": False}
    out = rep.upload()
    assert out["url"].endswith("/app/experiments/1") and service.experiments[0] == body
    recorder.store_content = True
    rep.upload()
    assert "recorded" in service.experiments[1]["rows"][0]


def test_cli_replay_and_compare(payouts, recorder, tmp_path, capsys):
    page = tmp_path / "replay.html"
    assert cli.main(["replay", "--html", str(page), "--to", "2999-01-01"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("signafAIde replay: claims-project") and "PASS: 21 records shown" in out
    assert page.read_text().startswith("<!doctype html>")
    mod = tmp_path / "cand.py"
    mod.write_text("def approve(claim_id, amount):\n    return {'approved': amount < 400}\n")
    assert cli.main(["compare", "--module", f"{mod}:approve", "--name", "approve_payout", "--upload"]) == 0
    out = capsys.readouterr().out
    assert "n 10: agreed 9, changed 1, errors 0 (90.0% agreement)" in out and "uploaded: " in out
    assert cli.main(["compare", "--module", "nope"]) == 1
