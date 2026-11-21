import atexit
import os
import socket

import pytest

from fake_service import FakeService
from signafaide import decorator, runtime, telemetry

AGENT_ENV = ("SIGNAFAIDE_", "CLAUDE", "CODEX_", "CURSOR_", "GEMINI_CLI", "COPILOT_", "GITHUB_COPILOT_", "WINDSURF_")


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A fresh project folder as the cwd, with no signafaide settings."""
    root = tmp_path / "Claims Project"
    root.mkdir()
    (root / ".git").mkdir()
    monkeypatch.chdir(root)
    for k in list(os.environ):
        if k.startswith(AGENT_ENV):
            monkeypatch.delenv(k)  # tests decide which coding agent they run under
    # The SDK turns test mode on by itself under pytest; these tests exercise the real recorder.
    monkeypatch.setenv("SIGNAFAIDE_TEST", "0")
    # Sessions stay in a temporary session.json, never in this machine's credential store.
    monkeypatch.setenv("SIGNAFAIDE_CREDENTIAL_STORE", "file")
    monkeypatch.delenv("TERM_PROGRAM", raising=False)
    monkeypatch.setattr(telemetry, "ADAPTERS", set())
    decorator._reset_tool_registry()  # tools wrapped by an earlier test are not this test's tool list
    return root


@pytest.fixture(autouse=True)
def _no_thread_outlives_its_test():
    """Every background thread a test starts (shipper, checks fetcher, tool refresher) has ended
    when the test ends: a thread left running would send to the next test's fake service once the
    port is reused, a failure that shows only now and then. Joined, never slept on."""
    import threading

    before = set(threading.enumerate())
    # Every recorder the test makes (fixtures, configure, init, a command it runs, or directly) is
    # stopped at its end like the fixtures' recorders.
    made = []
    real_init = runtime.Recorder.__init__

    def init(self, *a, **k):
        real_init(self, *a, **k)
        made.append(self)

    runtime.Recorder.__init__ = init
    try:
        yield
    finally:
        runtime.Recorder.__init__ = real_init
    for r in made:
        _stop(r)
    left = [t for t in threading.enumerate() if t not in before and t.name.startswith("signafaide-")]
    for t in left:
        t.join(15)
    alive = [t.name for t in left if t.is_alive()]
    assert not alive, f"background threads outlived the test: {alive}"


@pytest.fixture
def service():
    s = FakeService()
    yield s
    s.close()


@pytest.fixture
def dead_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"


def _recorder(service, monkeypatch, opt_in: bool):
    monkeypatch.setenv("SIGNAFAIDE_URL", service.url)
    r = runtime.configure(quiet=True, flush_interval=3600)
    if opt_in:
        r.create_sandbox()  # the person ran `signafaide init`
    return r


def _stop(r):
    r._stopped = True
    r._wake.set()
    r._tool_stop.set()
    r.checks.stop()
    atexit.unregister(r.close)
    runtime._default = None


@pytest.fixture
def recorder(project, service, monkeypatch):
    """The default recorder pointed at the fake service, after the person opted in (a sandbox
    key in .env, as `signafaide init` writes it); no timed flushes."""
    r = _recorder(service, monkeypatch, True)
    yield r
    _stop(r)


@pytest.fixture
def local_recorder(project, service, monkeypatch):
    """The default recorder with no API key: local only, nothing is sent."""
    r = _recorder(service, monkeypatch, False)
    yield r
    _stop(r)
