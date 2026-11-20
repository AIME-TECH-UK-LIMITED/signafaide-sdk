"""``signafaide check --ci``: the pull request check. It finds the agent's
tools the way ``protect`` does (``protect_cli.find_tools``), keeps the ones that look risky (they
pay, delete, send, run commands, push code, or edit secrets or config) and lists those not
protected: not decorated with ``@signafaide.protect`` (or ``record(strict=True)``), and not a
recorded tool the checks file protects (``"protect": true``, or a block rule kept on this machine
that names it with the tool in enforce mode, as ``protect --local`` writes). Reviewed exceptions are allowed by name, with a reason, in
the checks file's ``ci.allow``, or with ``--allow <tool>``.

It reads the code and the checks file only: no account, no key, nothing sent. ``--diff <base>``
keeps the tools whose code (or checks file entry) changed against a git base, for pull requests.
The TypeScript CLI checks TypeScript and JavaScript in the same way, with the same output."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union

from . import checks as C
from .checks_runtime import checks_path
from .coverage import declared_name
from .protect_cli import KIND_WORDS, FoundTool, agent_in_code, find_tools, name_words
from .records import agent_name

CI_FORMAT = "signafaide-ci/1"
_JS_EXTS = (".ts", ".tsx", ".js", ".mjs", ".cjs", ".mts", ".cts")
_SKIP_DIRS = {
    "node_modules",
    "dist",
    "build",
    "out",
    ".git",
    ".signafaide",
    "coverage",
    ".next",
    ".venv",
    "venv",
    "__pycache__",
    "target",
    "proof",
    "test",
    "tests",
    "__tests__",
    "spec",
}

# --- what looks risky ----------------------------------------------------------------------------

_MORE_PAYS = {"purchase", "buy", "checkout", "payroll"}
_MORE_RUNS = {"terminal", "subprocess", "cmd", "powershell", "sh"}
_CODE = {"push", "commit", "merge", "rebase", "git", "pr"}
_SECRETS = {"secret", "secrets", "credential", "credentials", "password", "passwords", "token", "tokens", "apikey"}
_CONFIG = {
    "config",
    "configs",
    "configuration",
    "settings",
    "setting",
    "env",
    "dotenv",
    "environment",
    "permission",
    "permissions",
    "iam",
}


def risk_of(name: str, kind: str) -> Optional[str]:
    """Why a tool looks risky, in words, from its name and kind; None when it does not. Reading
    tools never do; a tool that changes data does when it touches code, secrets or config."""
    if kind in ("pays", "deletes", "sends", "runs"):
        return KIND_WORDS[kind]
    if kind == "reads":
        return None
    w = set(name_words(name))
    if w & _MORE_PAYS:
        return KIND_WORDS["pays"]
    if w & _MORE_RUNS:
        return KIND_WORDS["runs"]
    if w & _CODE:
        return "pushes code"
    if w & _SECRETS or {"api", "key"} <= w:
        return "edits secrets"
    if w & _CONFIG:
        return "edits config"
    return None


# --- the result ----------------------------------------------------------------------------------


class CiError(Exception):
    pass


@dataclass
class CiResult:
    format: str
    language: str
    ok: bool
    root: str
    base: Optional[str]
    tools_found: int
    risky: int = 0
    protected: int = 0
    unprotected: List[dict] = field(default_factory=list)
    allowed: List[dict] = field(default_factory=list)
    #: Files of the other language, which the other CLI checks.
    other: Optional[dict] = None

    def to_json(self) -> dict:
        return asdict(self)


# --- the checks file -----------------------------------------------------------------------------


def _read_checks(root: Path) -> Tuple[Optional[dict], Optional[Path]]:
    p = checks_path(root)
    if p is None or not p.exists():
        return None, p
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        raise CiError(f"{p} is not JSON: {e}") from e
    err = C.checks_file_errors(doc)
    if err:
        raise CiError(f"{p}: {err}")
    return doc, p


def _protected_by_file(file: Optional[dict], tool: str) -> bool:
    """Whether the checks file protects the tool: ``"protect": true`` (signafAIde rules on its
    calls), or, as ``protect --local`` writes, its entry in enforce mode with a block rule on this
    machine that names it (``status`` says "this machine only")."""
    if not file:
        return False
    decl = declared_name(tool)
    ts = C.tool_settings(file, decl)
    if ts["strict"]:
        return True
    local = (file.get("rules") or {}).get("rules") or []
    return ts["mode"] == "enforce" and any(
        r.get("action") == "block" and (r.get("tools") is None or decl in r["tools"]) for r in local
    )


# --- where a tool is -----------------------------------------------------------------------------


def _span(t: FoundTool, cache: Dict[Path, Dict[int, Tuple[int, int]]]) -> Tuple[int, int]:
    """The first and last line of a tool's code: its decorators, its ``def`` and its body."""
    if t.file not in cache:
        spans: Dict[int, Tuple[int, int]] = {}
        try:
            for n in ast.walk(ast.parse(t.file.read_text())):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    first = min([d.lineno for d in n.decorator_list] + [n.lineno])
                    spans[n.lineno] = (first, n.end_lineno or n.lineno)
        except (OSError, SyntaxError, ValueError):
            pass
        cache[t.file] = spans
    return cache[t.file].get(t.line, (t.line, t.line))


def _fix(t: FoundTool, agent: str) -> str:
    deco = f"@signafaide.protect(agent={json.dumps(agent)})"
    if t.wrapped == "record":
        return f"change @signafaide.record to {deco} on def {t.name} (or: signafaide protect --tool {t.name})"
    where = " (under the framework's decorator)" if t.framework else ""
    return f"add {deco} right above def {t.name}{where} (or: signafaide protect --tool {t.name})"


def _agent(root: Path, found) -> str:
    named = agent_in_code(found, root)
    if named:
        return named
    try:
        m = re.search(r'^\s*name\s*=\s*"([^"]+)"', (root / "pyproject.toml").read_text(), re.M)
        if m:
            return agent_name(m.group(1))
    except OSError:
        pass
    return agent_name(root.name)


# --- the git base --------------------------------------------------------------------------------


def _git(root: Path, args: Sequence[str]) -> str:
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout


@dataclass
class Changes:
    #: Lines added or changed since the base, by absolute path; "all" for a new file.
    lines: Dict[Path, Union[Set[int], str]]
    #: The checks file as it was at the base (None when there was none).
    base_checks: Optional[dict]
    #: The commit compared against (the merge base of the base and HEAD, when there is one).
    commit: str


def changes_since(root: Path, base: str, checks_file: Optional[Path]) -> Changes:
    """What changed in the working tree against *base* (a branch, tag or commit), from the merge
    base so the base branch's own new commits do not count."""
    try:
        top = Path(_git(root, ["rev-parse", "--show-toplevel"]).strip())
    except (OSError, subprocess.CalledProcessError) as e:
        raise CiError(f"--diff needs a git repository; {root} is not in one") from e
    try:
        _git(root, ["rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"])
    except subprocess.CalledProcessError as e:
        raise CiError(
            f"--diff {base}: no such commit in this clone; fetch it first (in GitHub Actions: actions/checkout with fetch-depth: 0)"
        ) from e
    commit = base
    try:
        commit = _git(root, ["merge-base", base, "HEAD"]).strip() or base
    except subprocess.CalledProcessError:
        pass  # no merge base (a shallow clone): compare with the base itself
    lines: Dict[Path, Union[Set[int], str]] = {}
    cur: Optional[Set[int]] = None
    for ln in _git(
        root, ["-c", "core.quotepath=off", "diff", "--unified=0", "--no-color", "--no-ext-diff", "-M", commit, "--"]
    ).split("\n"):
        if ln.startswith("+++ "):
            p = ln[4:]
            if p == "/dev/null":
                cur = None
                continue
            cur = set()
            lines[(top / re.sub(r"^b/", "", p)).resolve()] = cur
            continue
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", ln)
        if m and cur is not None:
            start = int(m.group(1))
            n = 1 if m.group(2) is None else int(m.group(2))
            # Lines removed with nothing added in their place: the lines on either side changed.
            if n == 0:
                cur.update((start, start + 1))
            cur.update(range(start, start + n))
    for p in _git(root, ["ls-files", "--others", "--exclude-standard", "--full-name"]).split("\n"):
        if p.strip():
            lines[(top / p.strip()).resolve()] = "all"
    for p in _git(root, ["diff", "--name-only", "--diff-filter=A", "-M", commit, "--"]).split("\n"):
        if p.strip():
            lines[(top / p.strip()).resolve()] = "all"
    base_checks = None
    if checks_file is not None:
        rel = os.path.relpath(Path(checks_file).resolve(), top.resolve()).replace(os.sep, "/")
        try:
            doc = json.loads(_git(root, ["show", f"{commit}:{rel}"]))
            if not C.checks_file_errors(doc):
                base_checks = doc
        except (subprocess.CalledProcessError, ValueError):
            pass  # no checks file at the base
    return Changes(lines, base_checks, commit)


def _changed(ch: Changes, file: Path, span: Tuple[int, int]) -> bool:
    got = ch.lines.get(file.resolve())
    if got is None:
        return False
    if got == "all":
        return True
    return any(i in got for i in range(span[0], span[1] + 1))


def _count_files(root: Path, exts: Tuple[str, ...]) -> int:
    n = 0
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in _SKIP_DIRS]
        n += sum(1 for f in files if f.endswith(exts) and not f.endswith(".d.ts"))
        if n >= 2000:
            break
    return n


# --- the check -----------------------------------------------------------------------------------


def ci_check(root: Path, base: Optional[str] = None, allow: Sequence[str] = ()) -> CiResult:
    root = Path(root).resolve()
    if not root.is_dir():
        raise CiError(f"{root} is not a folder")
    checks, checks_file = _read_checks(root)
    found = find_tools(root)
    agent = _agent(root, found)
    ch = changes_since(root, base, checks_file) if base else None
    file_allow = {a["tool"]: a["reason"] for a in ((checks or {}).get("ci") or {}).get("allow", [])}
    cli_allow = set(allow)
    spans: Dict[Path, Dict[int, Tuple[int, int]]] = {}
    out = CiResult(CI_FORMAT, "python", True, str(root), base, len(found.tools))

    def rel(p: Path) -> str:
        try:
            return p.resolve().relative_to(root).as_posix()
        except ValueError:
            return str(p)

    for t in found.tools:
        why = risk_of(t.name, t.kind)
        if why is None:
            continue
        span = _span(t, spans)
        if ch is not None:
            if not _changed(ch, t.file, span) and _protected_by_file(checks, t.name) == _protected_by_file(
                ch.base_checks, t.name
            ):
                continue
        out.risky += 1
        # The checks file protects a tool whose calls go through signafaide: a recorded function,
        # or an MCP server tool (run through ``signafaide gateway``).
        via_file = _protected_by_file(checks, t.name) and (t.wrapped == "record" or t.framework == "MCP server")
        if t.wrapped == "protect" or via_file:
            out.protected += 1
            continue
        where = {"tool": t.name, "file": rel(t.file), "line": span[0]}
        reason = file_allow.get(declared_name(t.name), file_allow.get(t.name))
        if reason is not None or t.name in cli_allow:
            out.allowed.append(
                {
                    **where,
                    "why": why,
                    "reason": reason if reason is not None else "allowed on the command line (--allow)",
                    "from": "checks file" if reason is not None else "--allow",
                }
            )
            continue
        if t.wrapped == "record":
            state = "recorded, not protected"
        elif _protected_by_file(checks, t.name):
            state = "protected in signafaide.checks.json, but its code does not go through signafaide"
        else:
            state = "not protected"
        out.unprotected.append(
            {**where, "why": f"{why}; {state}", "fix": _fix(t, agent), "shape": t.shape, "framework": t.framework}
        )
    out.unprotected.sort(key=lambda u: (u["file"], u["line"]))
    out.allowed.sort(key=lambda u: (u["file"], u["line"]))
    out.ok = not out.unprotected
    js = _count_files(root, _JS_EXTS)
    if js:
        out.other = {"language": "javascript", "files": js, "command": "npx signafaide check --ci"}
    return out


def _n(k: int, one: str, many: Optional[str] = None) -> str:
    return f"{k} {one if k == 1 else (many or one + 's')}"


def ci_lines(r: CiResult) -> List[str]:
    """The lines ``check --ci`` prints: one per tool not protected, with its fix, then the total."""
    lines = [f"{u['file']}:{u['line']}: {u['tool']} {u['why']}. Fix: {u['fix']}" for u in r.unprotected]
    lines += [
        f"{a['file']}:{a['line']}: {a['tool']} {a['why']}; allowed ({a['from']}): {a['reason']}" for a in r.allowed
    ]
    scope = f" added or changed since {r.base}" if r.base else ""
    lang = "Python" if r.language == "python" else "TypeScript and JavaScript"
    if r.ok:
        lines.append(
            f"signafaide check --ci: passed. {_n(r.risky, 'risky tool')}{scope}: {r.protected} protected, {len(r.allowed)} allowed "
            f"({lang}, {_n(r.tools_found, 'tool')} found)."
        )
    else:
        lines.append(
            f"signafaide check --ci: failed. {_n(len(r.unprotected), 'risky tool')}{scope} not protected (of {r.risky}; {r.protected} protected, "
            f"{len(r.allowed)} allowed; {lang}, {_n(r.tools_found, 'tool')} found)."
        )
    if r.other:
        what = "Python file" if r.other["language"] == "python" else "TypeScript or JavaScript file"
        lines.append(
            f"note: {_n(r.other['files'], what)} not checked here; run {r.other['command']} for them (the GitHub Action runs both)."
        )
    if not r.ok:
        lines.append(
            'A reviewed exception: add { "tool": "<name>", "reason": "<why it is safe>" } to "ci": { "allow": [...] } in signafaide.checks.json.'
        )
    return lines
