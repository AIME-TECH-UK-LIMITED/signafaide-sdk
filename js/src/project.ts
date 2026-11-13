/** What a project is written in, and the exact adoption steps for it (MCP `signafaide_setup`, `signafaide_quickstart`). */

import * as fs from "node:fs";
import * as path from "node:path";

export const LANGUAGES = ["python", "typescript", "javascript"] as const;
export const FRAMEWORKS = ["plain", "langchain", "openai-agents", "vercel-ai"] as const;
export type Language = (typeof LANGUAGES)[number];
export type Framework = (typeof FRAMEWORKS)[number];

export interface Project {
  root: string;
  language: Language | null;
  framework: Framework;
  /** The install command for this project's package manager. */
  install: string;
  verify: string;
  /** signafaide is already a dependency. */
  installed: boolean;
  /** Functions whose names say they act (approve, send, delete...), as `file:line name`. */
  candidates: string[];
}

const read = (p: string): string => {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return "";
  }
};
const list = (dir: string): string[] => {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
};
const json = (s: string): any => {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
};
const has = (root: string, f: string): boolean => fs.existsSync(path.join(root, f));

/** Python dependency text (lowercased) from pyproject.toml, setup.py, Pipfile, requirements*.txt; null if none. */
function pythonDeps(root: string): string | null {
  const files = ["pyproject.toml", "setup.py", "setup.cfg", "Pipfile", ...list(root).filter((f) => /^requirements.*\.txt$/.test(f))].filter((f) => has(root, f));
  return files.length ? files.map((f) => read(path.join(root, f))).join("\n").toLowerCase() : null;
}

export function detectProject(root: string): Project {
  const pkg = has(root, "package.json") ? json(read(path.join(root, "package.json"))) : null;
  const deps: Record<string, string> = { ...(pkg?.dependencies ?? {}), ...(pkg?.devDependencies ?? {}) };
  const py = pythonDeps(root);
  let language: Language | null = null;
  let framework: Framework = "plain";
  let install = "";
  let verify = "";
  let installed = false;
  const jsDeps = Object.keys(deps).some((d) => d !== "signafaide");
  // A Python project without a dependency file (a script and maybe a package.json that only holds
  // signafaide for the MCP server) is still Python when its sources are Python and none are JS.
  const sources = [...list(root), ...list(path.join(root, "src"))];
  const pyOnly = py === null && !jsDeps && sources.some((f) => f.endsWith(".py")) && !sources.some((f) => /\.[cm]?[jt]sx?$/.test(f));
  if ((py !== null && !jsDeps) || pyOnly) {
    language = "python";
    installed = py !== null && /(^|["'\s,[])signafaide([<>=~!\s,"'\][;]|$)/m.test(py);
    if (/langchain|langgraph/.test(py ?? "")) framework = "langchain";
    else if (/openai-agents/.test(py ?? "")) framework = "openai-agents";
    [install, verify] = pythonInstall(root, py);
  } else if (pkg) {
    installed = "signafaide" in deps;
    language = has(root, "tsconfig.json") || "typescript" in deps ? "typescript" : "javascript";
    if ("@langchain/core" in deps || "langchain" in deps || "@langchain/langgraph" in deps) framework = "langchain";
    else if ("@openai/agents" in deps || "@openai/agents-core" in deps) framework = "openai-agents";
    else if ("ai" in deps) framework = "vercel-ai";
    const pm = has(root, "pnpm-lock.yaml") ? "pnpm add" : has(root, "yarn.lock") ? "yarn add" : has(root, "bun.lockb") || has(root, "bun.lock") ? "bun add" : "npm install";
    [install, verify] = [`${pm} signafaide`, "npx signafaide verify"];
  }
  return { root, language, framework, install, verify, installed, candidates: language ? findCandidates(root, language) : [] };
}

const VERBS =
  "approve|reject|deny|pay|payout|refund|charge|transfer|wire|send|email|notify|post|publish|delete|remove|drop|cancel|update|change|modify|" +
  "create|write|grant|revoke|escalate|book|order|purchase|buy|sell|issue|deploy|execute|submit|close|merge|ban|suspend";
const ACTION = new RegExp(`^_?(${VERBS})(_|[A-Z]|$)`);
const PY_DEF = /^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/;
const JS_DEF = /^\s*(?:export\s+)?(?:(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(|(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(|function|[A-Za-z_$][\w$]*\s*=>))/;
const SKIP = new Set(["node_modules", "venv", "env", "dist", "build", "__pycache__", "coverage", "site-packages"]);

/** Up to 15 functions whose names say they act, so the agent knows what to wrap. */
export function findCandidates(root: string, language: Language): string[] {
  const exts = language === "python" ? [".py"] : [".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx"];
  const re = language === "python" ? PY_DEF : JS_DEF;
  const out: string[] = [];
  let files = 0;
  const walk = (dir: string, depth: number): void => {
    for (const name of list(dir).sort()) {
      if (out.length >= 15 || files >= 2000) return;
      const p = path.join(dir, name);
      let st: fs.Stats;
      try {
        st = fs.statSync(p);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (depth < 6 && !SKIP.has(name) && !name.startsWith(".")) walk(p, depth + 1);
        continue;
      }
      if (!exts.includes(path.extname(name)) || /\.(test|spec|d)\.[a-z]+$/.test(name) || name.startsWith("test_") || st.size > 500_000) continue;
      files++;
      read(p)
        .split("\n")
        .forEach((line, i) => {
          const m = line.match(re);
          const fn = m && (m[1] ?? m[2]);
          if (fn && ACTION.test(fn) && out.length < 15) out.push(`${path.relative(root, p)}:${i + 1} ${fn}`);
        });
    }
  };
  walk(root, 0);
  return out;
}

/** The canonical snippet for a language and framework. */
export function snippet(language: Language, framework: Framework): string {
  if (language === "python") {
    switch (framework) {
      case "langchain":
        return `import signafaide

# @tool functions or BaseTool instances; the copies record every invoke and still work with bind_tools
tools = signafaide.wrap_tools([lookup_order, refund])
agent = create_agent(model, tools=tools)`;
      case "openai-agents":
        return `import signafaide
from agents import Agent

agent = Agent(name="support", tools=signafaide.wrap_tools([lookup_order, refund]))  # @function_tool tools`;
      default:
        return `import signafaide

@signafaide.record
def approve_payout(claim_id: str, amount: float): ...

# or wrap existing functions without touching their definitions:
approve_payout, escalate = signafaide.wrap_tools([approve_payout, escalate])

# a decision that is not a tool call:
signafaide.note("routing", {"reason": "amount over limit"})`;
    }
  }
  const ts = language === "typescript";
  switch (framework) {
    case "vercel-ai":
      return `import { wrapTools } from "signafaide";

const result = await generateText({ model, tools: wrapTools({ weather: tool({ inputSchema, execute }) }), prompt });`;
    case "openai-agents":
      return `import { wrapTools } from "signafaide";

const agent = new Agent({ name: "support", tools: wrapTools([lookupOrder, refund]) }); // tool({...}) from @openai/agents`;
    case "langchain":
      return `import { wrapTools } from "signafaide";

// tool(), DynamicStructuredTool or StructuredTool instances; the copies are still StructuredTools
const tools = wrapTools([lookupOrder, refund]);
const modelWithTools = model.bindTools(tools);`;
    default:
      return `import { note, record, wrapTools } from "signafaide";

const approvePayout = record(async (claimId${ts ? ": string" : ""}, amount${ts ? ": number" : ""}) => {
  /* ... */
}, { name: "approve_payout" });

// or wrap existing functions (object key = recorded name):
const tools = wrapTools({ approve_payout: approvePayout, escalate });

// a decision that is not a tool call:
note("routing", { reason: "amount over limit" });`;
  }
}

/** A Python project's install and verify commands. Never a bare `pip install`: most systems'
 * Python refuses it outside a virtual environment (PEP 668, "externally-managed-environment").
 * uv or Poetry projects use their tool; an existing virtual environment its own pip; otherwise
 * a new `.venv`. */
export function pythonInstall(root: string, deps: string | null, env: Record<string, string | undefined> = process.env): [string, string] {
  const pyproject = read(path.join(root, "pyproject.toml"));
  if (has(root, "uv.lock") || /^\[tool\.uv[\].]/m.test(pyproject)) return ["uv add signafaide", "uv run signafaide verify"];
  if (has(root, "poetry.lock") || /^\[tool\.poetry[\].]/m.test(pyproject)) return ["poetry add signafaide", "poetry run signafaide verify"];
  const record = has(root, "requirements.txt") ? ", and add signafaide to requirements.txt" : deps !== null && pyproject ? ", and add signafaide to pyproject.toml's dependencies" : "";
  const venv = [".venv", "venv", "env"].find((d) => has(root, path.join(d, "pyvenv.cfg")));
  if (venv) return [`${venv}/bin/python -m pip install signafaide${record}`, `${venv}/bin/signafaide verify`];
  const active = env.VIRTUAL_ENV;
  if (active && fs.existsSync(path.join(active, "pyvenv.cfg"))) {
    const v = path.relative(root, active);
    const shown = !v.startsWith("..") && !path.isAbsolute(v) ? v : active;
    return [`${shown}/bin/python -m pip install signafaide${record}`, `${shown}/bin/signafaide verify`];
  }
  // No virtual environment yet: make one. uv, when installed, does not need the python3-venv package.
  const uv = (env.PATH ?? "").split(path.delimiter).some((d) => d && fs.existsSync(path.join(d, "uv")));
  if (uv) return [`uv venv .venv && uv pip install --python .venv/bin/python signafaide${record}`, ".venv/bin/signafaide verify"];
  return [`python3 -m venv .venv && .venv/bin/python -m pip install signafaide${record}`, ".venv/bin/signafaide verify"];
}

export const installCommand = (language: Language): string =>
  language === "python" ? "uv add signafaide (uv projects), poetry add signafaide (Poetry), else: python3 -m venv .venv && .venv/bin/python -m pip install signafaide" : "npm install signafaide";
export const verifyCommand = (language: Language): string =>
  language === "python" ? "uv run signafaide verify, poetry run signafaide verify, or .venv/bin/signafaide verify" : "npx signafaide verify";
