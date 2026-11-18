"""The project note for coding agents (issue #67 step 2): one paragraph and three lines that
``signafaide protect`` and ``signafaide init`` add to the project's AGENTS.md / CLAUDE.md as a
marked block, after asking. The same text as the TypeScript SDK's ``NOTE`` (js/src/skill.ts) and
the repository's agents/AGENTS.md; a test keeps them equal."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, List, Tuple

SECTION_START = "<!-- signafaide:start -->"
SECTION_END = "<!-- signafaide:end -->"

PROTECT_CMD = {"ts": "npx signafaide protect", "py": "signafaide protect"}
AGENT_PROTECT_CMD = "npx signafaide protect --yes --tool <name> --limit-field amount --above 1000"

NOTE = (
    "## signafAIde\n\n"
    "This project uses signafAIde to check an AI agent's tool calls before they run. "
    "Use it when adding or changing a tool that pays, deletes, sends messages, runs commands, pushes code, or edits secrets or config: "
    "wrap that tool with protect(), and it runs only when the rules a person set allow it, with each call signed and recorded. "
    "Records stay on this machine in .signafaide/; nothing is sent and nothing is created online until a person opts in.\n\n"
    "- Install: `npm install signafaide` (TypeScript, JavaScript) or `uv add signafaide` (Python; `pip install signafaide` inside the "
    "project's virtual environment also works).\n"
    '- Wrap: `protect(payout, { args: ["payee", "amount"], agent: "my-agent" })` from "signafaide", or `@signafaide.protect(agent="my-agent")` '
    "above the function in Python.\n"
    f"- Make it work here: `{PROTECT_CMD['ts']}` (or `{PROTECT_CMD['py']}` in Python), run once by a person in a terminal; protected tools stop "
    f"until then. Without a terminal, `{AGENT_PROTECT_CMD}` writes the code and a rule that starts Calibrating (it blocks nothing until a "
    "person turns it On).\n"
)

#: The question that adds the note (a scripted prompter with no answer left takes its default).
NOTE_QUESTION = "Add the signafAIde note to"

#: The note's first sentence: a file that holds it outside a marked block already has the note.
_NOTE_KEY = NOTE.split("\n")[2].split(". ")[0]

NOTE_FILES = ("AGENTS.md", "CLAUDE.md")

#: Claude Code's import line: a CLAUDE.md that holds it reads AGENTS.md, so it has the note too.
CLAUDE_IMPORT = "@AGENTS.md"


def _imports_agents(f: Path) -> bool:
    return f.name == "CLAUDE.md" and f.exists() and any(l.strip() == CLAUDE_IMPORT for l in f.read_text(encoding="utf-8").splitlines())


def note_section() -> str:
    return f"{SECTION_START}\n{NOTE.strip()}\n{SECTION_END}\n"


def note_files(root: Path) -> List[Path]:
    """The project's AGENTS.md and CLAUDE.md that exist, or a new AGENTS.md when neither does."""
    have = [f for f in NOTE_FILES if (root / f).exists()]
    return [root / f for f in (have or ["AGENTS.md"])]


def note_what(file: str, result: str, the: bool = False) -> str:
    """What a file ``offer_note`` wrote holds, in words: a CLAUDE.md made new holds only the import."""
    if file == "CLAUDE.md" and result == "created":
        return f"just {CLAUDE_IMPORT}, so Claude Code reads the same note"
    return ("the " if the else "") + "signafAIde note for coding agents (a marked block)"


def merged(prev: str) -> str:
    """*prev* with the note's marked block: replaced in place if present, else appended. Unchanged
    when the file already holds the note's text without the markers (never twice)."""
    section = note_section()
    a = prev.find(SECTION_START)
    b = prev.find(SECTION_END, a) if a >= 0 else -1
    if a >= 0 and b > a:
        end = b + len(SECTION_END)
        if prev[end:end + 1] == "\n":
            end += 1
        return prev[:a] + section + prev[end:]
    if _NOTE_KEY in prev:
        return prev
    return (prev.rstrip("\n") + "\n\n" + section) if prev else section


def offer_note(root: Path, prompt: Any, out: Callable[[str], None]) -> List[Tuple[str, str]]:
    """``protect`` and ``init``: add the note to the project's instructions files, after asking.
    Returns ``(file, "created" | "updated")`` for each file written; a file that already has the
    note is not asked about. A symbolic link is never written through."""
    todo: List[Tuple[Path, str, str]] = []
    fresh = not any((root / f).exists() for f in NOTE_FILES)
    for f in note_files(root):
        if _imports_agents(f):
            continue
        prev = f.read_text(encoding="utf-8") if f.exists() else ""
        nxt = merged(prev)
        if nxt != prev or not f.exists():
            todo.append((f, prev, nxt))
    if fresh and todo:
        # no instructions file at all: AGENTS.md has the note, CLAUDE.md just imports it for Claude Code
        todo.append((root / "CLAUDE.md", "", CLAUDE_IMPORT + "\n"))
    if not todo:
        return []
    names = " and ".join(f.name for f, _, _ in todo)
    out(f"Agents     {names}: a short marked block that tells coding agents to protect the tools that pay, delete, send, run commands "
        "or push code, and how.")
    if not prompt.confirm(f"{NOTE_QUESTION} {names}?", True):
        out("           Not added; run this command again to add it.")
        return []
    done: List[Tuple[str, str]] = []
    for f, prev, nxt in todo:
        if f.is_symlink():
            out(f"           {f.name} is a symbolic link: not written; add the note by hand.")
            continue
        existed = f.exists()
        f.write_text(nxt, encoding="utf-8")
        done.append((f.name, "updated" if existed else "created"))
    return done
