"""The claim step: why to claim, and how long an unclaimed sandbox has left (init, status,
claim, verify). The TypeScript tests (claim.test.ts) check the same words."""

import json
import time

import pytest

import signafaide
from fake_service import _rfc3339
from signafaide import _claim, runtime
from signafaide.cli import main

WHY = "claiming is free and needs no card: the sandbox moves into your own organisation and stops expiring, and you get the console, live keys and auditor links"
KEPT = "Records on this machine are kept and still verify"
DONE = "claim: done (this sandbox belongs to an organisation now)"


def left(n, at):
    return f"{n} days left: an unclaimed sandbox and its records on the service are deleted on {_claim.long_date(at)}. {KEPT}"


@pytest.fixture
def cli(project, service, monkeypatch, capsys):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)

    def run(*args):
        code = main(list(args))
        out = capsys.readouterr()
        # `init` also says how tool-call checks are set up (tested in test_checks): not a claim line.
        return code, [x for x in out.out.splitlines() if not x.startswith("tool-call checks: ")], out.err.splitlines()

    yield run
    runtime._default = None


@pytest.fixture
def box(project):
    """Read and write the project's sandbox.json."""
    f = project / ".signafaide" / "sandbox.json"

    class Box:
        def __call__(self):
            return json.loads(f.read_text())

        def save(self, v):
            f.write_text(json.dumps(v, indent=2))

    return Box()


def again(project):
    return (
        f"{KEPT}. To carry on with the service: remove SIGNAFAIDE_API_KEY from {project / '.env'} (or from the environment), "
        "run `signafaide init` for a new sandbox and claim it"
    )


def one_project(service):
    return next(iter(service.projects.values()))


def test_dates_and_days():
    assert _claim.CLAIM_WHY == WHY
    assert _claim.long_date("2026-12-15T09:30:00.000Z") == "15 December 2026"
    assert _claim.long_date("2027-01-01T00:00:00.000Z") == "1 January 2027"
    now = 1796292000.0  # 2026-12-03T10:00:00Z
    assert _rfc3339(now) == "2026-12-03T10:00:00.000Z"
    assert _claim.days_left("2026-12-15T09:30:00.000Z", now) == 12
    assert _claim.days_left("2026-12-03T10:00:01.000Z", now) == 1
    assert _claim.days_left("2026-12-03T09:00:00.000Z", now) == 0
    assert _claim.parse_expiry("2026-12-15T09:30:00.000Z") == "2026-12-15T09:30:00.000Z"
    for bad in (None, 30, "", "soon", "2026-13-45T00:00:00Z", "x" * 50):
        assert _claim.parse_expiry(bad) is None


def test_init_says_why_and_how_long_and_the_others_repeat_it(cli, project, service, box):
    code, out, _ = cli("init")
    assert code == 0
    at, url = box()["expires_at"], box()["claim_url"]
    assert at == one_project(service)["expires_at"]
    assert out[0] == f"sandbox ready at {service.url}, key saved to {project / '.env'}; claim it at {url}"
    assert out[1:3] == [WHY, left(30, at)]
    assert out[3].startswith("By creating a sandbox you agree")

    code, out, _ = cli("init")  # again: the key is there
    assert out[-3].startswith("key found (sfa_test_0000...); claim the sandbox at http") and out[-2:] == [
        WHY,
        left(30, at),
    ]
    assert cli("status")[1][-3:] == [f"claim: {url}", WHY, left(30, at)]
    assert cli("claim")[:2] == (0, [url, WHY, left(30, at)])

    signafaide.record(lambda x: x, name="act")(1)
    cli("flush")
    code, out, _ = cli("verify")
    assert code == 0 and out[-4].startswith("PASS") and out[-3:] == [f"claim: {url}", WHY, left(30, at)]

    # --json: the same facts as data, and no prose.
    code, out, _ = cli("verify", "--json")
    doc = json.loads("\n".join(out))
    assert code == 0 and doc["result"] == "PASS"
    assert doc["sandbox"] == {"claim_url": url, "claimed": False, "expires_at": at, "days_left": 30}
    assert "claiming is free" not in "\n".join(out)

    # Twelve days before the end.
    soon = _rfc3339(time.time() + 12 * 86_400 - 60)
    one_project(service)["expires_at"] = soon
    assert cli("status")[1][-1] == left(12, soon)
    assert box()["expires_at"] == soon
    one_project(service)["expires_at"] = _rfc3339(time.time() + 3600)
    assert cli("status")[1][-1].startswith("1 day left: an unclaimed sandbox")


def test_a_witness_without_expires_at_gets_no_days(cli, project, service, box):
    service.sandbox_days = None
    code, out, _ = cli("init")
    assert code == 0 and "claim it at " in out[0] and out[1] == WHY and out[2].startswith("By creating a sandbox")
    assert "expires_at" not in box()
    for cmd in ("status", "claim", "init"):
        text = "\n".join(cli(cmd)[1])
        assert WHY in text and " left" not in text and "deleted on" not in text
    signafaide.record(lambda x: x, name="act")(1)
    cli("flush")
    assert cli("verify")[1][-2:] == [f"claim: {box()['claim_url']}", WHY]
    assert json.loads("\n".join(cli("verify", "--json")[1]))["sandbox"] == {
        "claim_url": box()["claim_url"],
        "claimed": False,
        "expires_at": None,
        "days_left": None,
    }
    # A value that is not a time is not used either.
    one_project(service)["expires_at"] = "in a month"
    text = "\n".join(cli("status")[1])
    assert " left" not in text and "deleted on" not in text and "expires_at" not in box()


def test_a_sandbox_from_an_older_sdk_learns_its_time_from_status(cli, service, box):
    cli("init")
    old = box()
    at = old.pop("expires_at")
    box.save(old)
    assert cli("status")[1][-1] == left(30, at)
    assert box()["expires_at"] == at


def test_claimed_is_done_with_no_countdown(cli, service, box):
    cli("init")
    signafaide.record(lambda x: x, name="act")(1)
    cli("flush")
    one_project(service)["claimed"] = True
    out = cli("status")[1]
    assert out[-1] == DONE and not any(
        " left" in line or "deleted on" in line or "claiming is free" in line for line in out
    )
    assert box()["claimed"] is True and "expires_at" not in box()
    assert cli("claim")[:2] == (0, [DONE])
    assert cli("verify")[1][-1].startswith("PASS")
    assert json.loads("\n".join(cli("verify", "--json")[1]))["sandbox"] == {
        "claim_url": box()["claim_url"],
        "claimed": True,
        "expires_at": None,
        "days_left": None,
    }
    assert cli("init")[1] == [f"key found (sfa_test_0000...); {DONE}"]


def test_expired_says_what_happens_and_how_to_carry_on(cli, project, service, box):
    cli("init")
    signafaide.record(lambda x: x, name="act")(1)
    cli("flush")
    past = _rfc3339(time.time() - 3600)
    one_project(service)["expires_at"] = past
    expired = [
        f"claim: this sandbox expired on {_claim.long_date(past)} without being claimed, so its claim link no longer works. "
        "The service deletes an expired sandbox and its records there within a day, and from then on refuses its key (invalid_key)",
        again(project),
    ]
    # Before the service's daily cleanup the key still answers.
    assert cli("status")[1][-2:] == expired
    # After it the key is refused (401 invalid_key): the same words, from the saved time.
    service.cleanup()
    assert not service.projects
    assert cli("status")[1][-2:] == expired
    assert cli("claim") == (1, [], expired)
    # Local records still verify, and the lines follow the result.
    code, out, _ = cli("verify")
    assert code == 0 and out[-3].startswith("PASS") and out[-2:] == expired
    assert json.loads("\n".join(cli("verify", "--json")[1]))["sandbox"] == {
        "claim_url": box()["claim_url"],
        "claimed": False,
        "expires_at": past,
        "days_left": 0,
    }

    # A sandbox whose time was never saved (an older SDK or witness): the refusal is what is known.
    old = box()
    old.pop("expires_at")
    box.save(old)
    assert cli("status")[1][-2:] == [
        "claim: the service refuses this sandbox's key (invalid_key). The service deletes an unclaimed sandbox and its records there "
        "when it expires, and this one had not been claimed when this machine last asked",
        again(project),
    ]

    # Carrying on as the line says: remove the key, init again; the old chain stays and verifies.
    env = project / ".env"
    env.write_text(
        "\n".join(line for line in env.read_text().split("\n") if not line.startswith("SIGNAFAIDE_API_KEY="))
    )
    runtime._default = None
    code, out, _ = cli("init")
    assert code == 0 and out[2] == left(30, box()["expires_at"])
    signafaide.record(lambda x: x, name="act")(2)
    assert cli("flush")[0] == 0
    assert cli("verify")[0] == 0


def test_past_its_time_while_the_service_cannot_be_asked(cli, service, box, dead_url, monkeypatch):
    cli("init")
    past = _rfc3339(time.time() - 3600)
    box.save(box() | {"expires_at": past})
    monkeypatch.setenv("SIGNAFAIDE_URL", dead_url)
    runtime._default = None
    assert cli("claim")[1] == [
        box()["claim_url"],
        f"this sandbox was due to be deleted on {_claim.long_date(past)} unless it was claimed first, and the service could not be asked "
        f"just now; run `signafaide status` when it can be reached. {KEPT}",
    ]
