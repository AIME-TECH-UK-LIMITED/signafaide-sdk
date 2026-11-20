// Writes the Claude Code plugin's SKILL.md, the project note files in agents/ and the organisation
// note files in agents/team/ from src/skill.ts: `npm run plugin`.
import * as fs from "node:fs";
import { NOTE, cursorNoteRule, llmsSnippet, pluginSkill, teamFiles } from "../src/skill.ts";

const files: [string, string][] = [
  ["../../plugin/skills/signafaide/SKILL.md", pluginSkill()],
  ["../../agents/AGENTS.md", NOTE],
  ["../../agents/CLAUDE.md", NOTE],
  ["../../agents/cursor-rules.mdc", cursorNoteRule()],
  ["../../agents/llms-snippet.md", llmsSnippet()],
  ...Object.entries(teamFiles()).map(([rel, text]): [string, string] => [`../../agents/team/${rel}`, text]),
];
for (const [rel, text] of files) {
  const file = new URL(rel, import.meta.url);
  fs.mkdirSync(new URL(".", file), { recursive: true });
  fs.writeFileSync(file, text);
  console.log(`wrote ${file.pathname}`);
}
