// Writes the Claude Code plugin's SKILL.md from src/skill.ts: `npm run plugin`.
import * as fs from "node:fs";
import { pluginSkill } from "../src/skill.ts";

const file = new URL("../../plugin/skills/signafaide/SKILL.md", import.meta.url);
fs.writeFileSync(file, pluginSkill());
console.log(`wrote ${file.pathname}`);
