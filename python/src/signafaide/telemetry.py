"""The ``X-Signafaide-Client`` header and usage events.

Sent: the SDK name and version, the language and runtime version, the framework
adapter in use, the coding agent that set the project up, and how the request was
made (sdk, cli or mcp). CLI ``verify`` and ``export`` also send one event naming the
command. Never sent: content, file paths, hostnames or user names.
``SIGNAFAIDE_TELEMETRY=0`` drops the adapter, the agent, the strict flag and the events.
"""

from __future__ import annotations

import os
import platform
from typing import Iterable, Mapping, Optional

from ._version import __version__

HEADER = "X-Signafaide-Client"
SDK = "signafaide-python"
ADAPTERS: set = set()  # framework adapters used in this process ("langchain", "openai-agents")

# Checked in order: an agent that runs inside an editor terminal (Claude Code in
# Cursor) must win over the editor.
_AGENTS = (
    ("claude-code", lambda e: e.get("CLAUDECODE") == "1" or _prefix(e, "CLAUDE_CODE_")),
    ("codex", lambda e: _prefix(e, "CODEX_", skip=("CODEX_COMPANION_",))),
    ("gemini-cli", lambda e: _prefix(e, "GEMINI_CLI")),
    ("copilot", lambda e: _prefix(e, "COPILOT_") or _prefix(e, "GITHUB_COPILOT_")),
    ("windsurf", lambda e: _prefix(e, "WINDSURF_") or e.get("TERM_PROGRAM", "").lower() == "windsurf"),
    ("cursor", lambda e: _prefix(e, "CURSOR_") or e.get("TERM_PROGRAM", "").lower() == "cursor"),
)


def _prefix(env: Mapping[str, str], prefix: str, skip: Iterable[str] = ()) -> bool:
    return any(k.startswith(prefix) and not any(k.startswith(s) for s in skip) for k in env)


def detect_agent(env: Optional[Mapping[str, str]] = None) -> str:
    """The coding agent whose environment this is, or ``unknown``."""
    env = os.environ if env is None else env
    return next((name for name, test in _AGENTS if test(env)), "unknown")


def enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    env = os.environ if env is None else env
    return env.get("SIGNAFAIDE_TELEMETRY", "").strip() != "0"


def adapter_field() -> str:
    return ",".join(sorted(ADAPTERS)) or "none"


def client_header(
    *,
    via: str = "sdk",
    adapter: str = "none",
    agent: str = "unknown",
    strict: bool = False,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """``signafaide-python/<v> (python <v>; adapter=<a>; agent=<a>; via=<v>[; strict=1])``;
    with telemetry off, adapter, agent and strict are left out."""
    on = enabled(env)
    parts = [f"python {platform.python_version()}"]
    if on:
        parts += [f"adapter={adapter or 'none'}", f"agent={agent or 'unknown'}"]
    parts.append(f"via={via}")
    if on and strict:
        parts.append("strict=1")
    return f"{SDK}/{__version__} ({'; '.join(parts)})"
