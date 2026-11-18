import { tool } from "ai";
import { z } from "zod";

export const gitPush = tool({
  description: "Push the current branch to the remote.",
  inputSchema: z.object({ branch: z.string() }),
  execute: async ({ branch }) => `pushed ${branch}`,
});
