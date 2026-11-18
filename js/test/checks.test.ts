/**
 * Tool-call checks (SPEC §2.8, §3.5, §8, §10, §11): every client-side case of `vectors.json`
 * `checks`, read with the literal-aware `parseJson`, as the Rust core and the Python SDK read them.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import * as C from "../src/checks.js";
import { COLLECT_PATTERNS, CONCEAL_PATTERNS, INSTRUCTION_PATTERNS, NAME_SCRIPTS, SHADOW_PATTERNS, SHADOW_REF_PATTERNS } from "../src/scan.js";
import { INSTRUCTION_CONFUSABLES } from "../src/confusables.js";
import * as W from "../src/words.js";
import { hashJson, sha256Hex, signedMessage, verifySig } from "../src/crypto.js";
import { canonicalize, parseJson } from "../src/jcs.js";
import { envelopeErrors, receiptErrors, recordErrors, recordHash } from "../src/records.js";

const file = path.resolve(__dirname, "../../spec/vectors.json");
const v = parseJson(fs.readFileSync(file, "utf8"));
const c = v.checks;
const serviceKeys = v.keys_document.keys;
const svc = v.keys[1].public_key;
const plain = (x: unknown): any => JSON.parse(JSON.stringify(x));

function rebuild(value: any, tokens: Record<string, { parts: string[] }>): any {
  if (typeof value === "string") {
    for (const [tid, t] of Object.entries(tokens)) value = value.split(`<${tid}>`).join(t.parts.join(""));
    return value;
  }
  if (Array.isArray(value)) return value.map((x) => rebuild(x, tokens));
  if (value && typeof value === "object" && value.constructor === Object) return Object.fromEntries(Object.entries(value).map(([k, x]) => [k, rebuild(x, tokens)]));
  return value;
}

describe("vectors.json checks", () => {
  it("signatures of the new domains", () => {
    expect(c.signatures.map((s: any) => s.domain)).toEqual(["ruling", "rules", "fingerprints"]);
    for (const s of c.signatures) {
      expect(Buffer.from(signedMessage(s.domain, s.hash)).toString("hex")).toBe(s.message_hex);
      expect(verifySig(svc, s.domain, s.hash, s.sig)).toBe(true);
    }
    for (const s of c.cross_domain) expect(verifySig(svc, s.verify_domain, s.hash, s.sig)).toBe(false);
  });

  it("conditions", () => {
    const inp = c.conditions.input;
    for (const t of c.conditions.cases) {
      expect(C.conditionErrors(t.condition), t.name).toBeNull();
      expect(C.condition(t.condition, C.resolve(inp, t.condition.field)), t.name).toEqual(t.expect);
    }
  });

  it("evaluation, modes and client rule entries", () => {
    const ev = c.evaluation;
    for (const t of ev.cases) {
      const doc = ev.rule_sets[t.rule_set];
      let count: ((lim: any) => number) | undefined;
      if (t.where === "witness") {
        const now = Date.parse(ev.now);
        count = (lim) =>
          t.history.filter((h: any) => {
            const same = lim.per === "agent" ? h.agent === t.agent : lim.per === "tool" ? h.tool === t.tool : h.agent === t.agent && h.tool === t.tool;
            const at = Date.parse(h.server_time);
            return same && now - lim.seconds * 1000 < at && at <= now;
          }).length;
      }
      const e = C.evaluate(doc, t.agent, t.tool, (p) => C.resolve(t.input, p), count);
      expect(plain({ result: e.result, basis: e.basis, matched: e.matched }), t.name).toEqual(plain(t.expect));
      // A document without states and exceptions never names a rule in the 1.1 lists.
      expect([e.would_block, e.not_calibrated, e.excepted], t.name).toEqual([[], [], []]);
    }
    for (const m of c.modes) expect(C.applyMode(m.check_result, m.mode)).toEqual(plain(m.expect));
    const cre = c.client_rule_entries;
    for (const t of cre.cases) {
      const doc = cre.rule_sets[t.rule_set];
      const local = t.set === "local";
      const mode = C.entryMode(doc.mode, t.strict, local);
      const e = C.clientRuleEntry(doc, mode, local ? "local" : doc.set, t.agent, t.tool, t.input);
      expect(plain(e), t.name).toEqual(plain(t.expect.entry));
      expect(e.result !== "block", t.name).toBe(t.expect.runs);
    }
  });

  it("rule set documents and updates", () => {
    for (const k of ["v1", "v2"]) {
      const e = c.rule_sets[k];
      expect(C.ruleSetErrors(e.rules)).toBeNull();
      expect(canonicalize(e.rules)).toBe(e.rules_jcs);
      expect(hashJson(e.rules)).toBe(e.rules_hash);
      expect(verifySig(svc, "rules", e.rules_hash, e.sig)).toBe(true);
    }
    for (const t of c.rule_sets_invalid) expect(C.ruleSetErrors(t.rules), t.name).not.toBeNull();
    const u = c.rule_set_updates;
    for (const t of u.cases) expect(C.acceptRules(t.held, t.offered, serviceKeys, u.project, u.env), t.name).toBe(t.expect);
  });

  it("fingerprint exceptions of the held rule set (§10.1): the client's fingerprint check", () => {
    const fe = c.fingerprint_exceptions;
    const listed = C.listedSet(fe.fingerprint_entries);
    for (const t of fe.cases) {
      const excepted = t.exceptions === null ? undefined : C.exceptedSet({ fingerprint_exceptions: t.exceptions });
      expect(C.fingerprintFindingsIn(t.tool, listed, excepted), t.name).toEqual(t.expect);
    }
    expect(C.ruleSetErrors(c.rulings.rule_sets.excepted)).toBeNull();
  });

  it("disclosure", () => {
    const docs: Record<number, any> = { 1: c.rule_sets.v1.rules, 2: c.rule_sets.v2.rules };
    for (const t of c.disclosure) {
      const need = C.neededFields(docs[t.rules_version], t.agent, t.tool);
      expect({ disclosed: need.filter((p) => t.disclose.includes(p)), missing: need.filter((p) => !t.disclose.includes(p)) }, t.name).toEqual(plain(t.expect));
    }
    const d = c.disclosed;
    expect(canonicalize(d.values)).toBe(d.values_jcs);
    expect(C.disclosedHash(d.values, d.salt)).toBe(d.disclosed_hash);
    expect(C.disclosedHash(d.absent_field.values, d.absent_field.salt)).toBe(d.absent_field.disclosed_hash);
  });

  it("tool fingerprints, changed tool and the shared list", () => {
    for (const t of c.tool_fingerprints) {
      const tool = t.tool;
      expect(C.toolFingerprints(tool.name, tool.description, tool.input_schema, t.server_info), t.name).toEqual(plain(t.expect));
      if ("stripped_schema_jcs" in t) expect(canonicalize(C.stripSchema(tool.input_schema))).toBe(t.stripped_schema_jcs);
    }
    const ct = c.changed_tool;
    for (const t of ct.cases) expect(C.changedToolFindings(t.fingerprints, ct.approved[t.tool] ?? null), t.name).toEqual(plain(t.expect));
    const fl = c.fingerprint_list;
    for (const t of fl.cases) {
      let held = C.emptyList();
      let err: string | null = null;
      for (const it of t.apply) {
        [held, err] = C.applyList(held, it, serviceKeys);
        if (err) break;
      }
      expect({ error: err, seq: held.seq, state_hash: C.stateHash(held.entries) }, t.name).toEqual(plain(t.expect));
    }
    expect(C.stateHash(fl.final_entries)).toBe(fl.final_state_hash);
  });

  it("envelopes with checks, the ruled record and rulings", () => {
    for (const t of c.envelopes_with_checks.valid) {
      expect(envelopeErrors(t.envelope), t.name).toEqual([]);
      expect(hashJson(t.envelope)).toBe(t.record_hash);
    }
    for (const t of c.envelopes_with_checks.invalid) expect(envelopeErrors(t.envelope), t.name).not.toEqual([]);
    const rr = c.ruled_record;
    expect(recordErrors(rr.record)).toEqual([]);
    expect(receiptErrors(rr.receipt)).toEqual([]);
    expect(canonicalize(rr.record.envelope)).toBe(rr.envelope_jcs);
    expect(recordHash(rr.record)).toBe(rr.record_hash);
    const g = rr.receipt.ruling;
    expect(C.rulingErrors(g)).toBeNull();
    expect(canonicalize(g)).toBe(rr.ruling_jcs);
    expect(hashJson(g)).toBe(rr.ruling_hash);
    expect(verifySig(svc, "ruling", rr.ruling_hash, rr.receipt.ruling_sig)).toBe(true);
    expect(C.disclosedErrors(rr.record, rr.record.content)).toBeNull();
    for (const t of rr.tampered) expect(verifySig(svc, "ruling", hashJson(t.ruling), t.ruling_sig) && t.ruling.record_hash === rr.record_hash, t.name).toBe(false);
    for (const t of c.rulings.cases) {
      const ruling = { v: 1, record_hash: "00".repeat(32), batch_hash: "11".repeat(32), server_time: c.rulings.now, reason: "x", ...t.expect };
      expect(C.rulingErrors(ruling), t.name).toBeNull();
    }
  });

  it("local checks: secret, address, hidden instruction", () => {
    const lc = c.local_checks;
    for (const [tid, t] of Object.entries<any>(lc.tokens)) expect(sha256Hex(new TextEncoder().encode(t.parts.join(""))), tid).toBe(t.sha256);
    expect(lc.secret_formats.map((f: any) => f.id)).toEqual([...C.SECRET_FORMATS.map((f) => f[0]), ...C.TEXT_FORMATS, ...C.CONTEXT_FORMATS]);
    C.SECRET_FORMATS.forEach(([fid, pat, issuers], i) => {
      const f = lc.secret_formats[i];
      expect(f.pattern, fid).toBe(pat);
      if (fid !== "signafaide_key") expect(f.issuers, fid).toEqual([...issuers]);
    });
    for (const t of lc.secret) expect(C.secretFindings(rebuild(t.input, lc.tokens), "witness.example"), t.name).toEqual(plain(t.expect));
    for (const t of lc.address) expect(C.addressFindings(t.input, t.allow.hosts, t.allow.cidrs), t.name).toEqual(plain(t.expect));
    for (const t of lc.hidden_instruction) expect(C.hiddenFindings(t.result), t.name).toEqual(plain(t.expect));
    // spec 1.1
    for (const t of lc.secret_result) expect(C.secretFindings(rebuild(t.result, lc.tokens), "witness.example", true), t.name).toEqual(plain(t.expect));
    for (const t of lc.definitions) expect(C.definitionFindings(t.definition, { others: t.others ?? [], approved: t.approved ?? [] }), t.name).toEqual(plain(t.expect));
    expect(lc.instruction_patterns).toEqual([...INSTRUCTION_PATTERNS]);
    // spec 1.1, benchmark batch 2
    for (const t of lc.arguments) expect(C.argumentFindings(t.input), t.name).toEqual(plain(t.expect));
    for (const t of lc.notes) {
      const f = t.in === "arguments" ? C.argumentFindings(t.value) : C.hiddenFindings(t.value);
      expect(C.callNotes(t.tool, t.in, f), t.name).toEqual(plain(t.expect));
    }
    expect(lc.shadow_patterns).toEqual([...SHADOW_PATTERNS]);
    expect(lc.shadow_ref_patterns).toEqual([...SHADOW_REF_PATTERNS]);
    expect(lc.instruction_confusables).toEqual(INSTRUCTION_CONFUSABLES.map(([c, l]) => [c, l]));
    // spec 1.1, benchmark batch 3
    expect(lc.covert_patterns).toEqual({ collect: [...COLLECT_PATTERNS], conceal: [...CONCEAL_PATTERNS] });
    expect(lc.name_scripts).toEqual(NAME_SCRIPTS.map(([n, rs]) => [n, rs.map(([a, b]) => [a, b])]));
  });

  it("the secret check's issuer rule for signafAIde keys", () => {
    const tok = "sfa_test_" + "a1B2".repeat(8);
    expect(C.secretFindings({ k: tok }, "witness.example").found).toEqual(["signafaide_key"]);
    expect(C.secretFindings({ u: "https://witness.example/v1/records", k: tok }, "witness.example")).toEqual({ result: "allow", found: [] });
    expect(C.secretFindings({ u: "https://other.example/", k: tok }, "witness.example").found).toEqual(["signafaide_key"]);
  });

  it("verifier lines", () => {
    const vl = c.verifier_lines;
    const out: Record<string, unknown> = {};
    const lines: string[] = [];
    for (const agent of ["agent-a", "agent-b", "agent-c"]) {
      const items = vl.records
        .filter((r: any) => r.record.agent === agent)
        .map((r: any) => ({ seq: r.record.seq, kind: r.record.kind, checks: r.record.checks, decision_seq: r.record.ref_seq ?? null, ruling: r.ruling }));
      const j = C.agentChecks(items);
      if (j) {
        out[agent] = j;
        lines.push(...C.checksLines(agent, j));
      }
    }
    expect(lines).toEqual(vl.expect.checks_lines);
    expect(plain(out)).toEqual(plain(vl.expect.checks));
  });

  it("spec 1.1: rule states, exceptions, rulings, client entries and disclosure", () => {
    const rs = c.rule_states;
    for (const t of rs.states) {
      const doc = rs.rule_sets[t.rule_set];
      expect(C.ruleSetErrors(doc), t.name).toBeNull();
      expect(Object.fromEntries(doc.rules.map((r: any) => [r.id, C.ruleState(doc, r)])), t.name).toEqual(t.expect);
    }
    for (const t of rs.evaluation) {
      const doc = rs.rule_sets[t.rule_set];
      const e =
        t.where === "witness"
          ? C.evaluate(doc, "agent-a", t.tool, (p) => (p in t.input ? t.input[p] : C.ABSENT), () => 0, (p) => t.available.includes(p))
          : C.evaluate(doc, "agent-a", t.tool, (p) => C.resolve(t.input, p));
      expect(plain(e), t.name).toEqual(plain(t.expect));
    }
    for (const t of rs.client_rule_entries) {
      const doc = rs.rule_sets[t.rule_set];
      const e = C.clientRuleEntry(doc, C.entryMode(doc.mode, t.strict, false), doc.set, "agent-a", "approve_payout", t.input);
      expect(plain(e), t.name).toEqual(plain(t.expect));
    }
    for (const t of rs.disclosure) expect(C.disclosure(rs.rule_sets[t.rule_set], "agent-a", "approve_payout", t.disclose), t.name).toEqual(plain(t.expect));
    for (const t of rs.ruling_shapes.valid) expect(C.rulingErrors(t.ruling), t.name).toBeNull();
    for (const t of rs.ruling_shapes.invalid) expect(C.rulingErrors(t.ruling), t.name).not.toBeNull();
    for (const t of rs.rulings) {
      const g = { v: 1, record_hash: "00".repeat(32), batch_hash: "11".repeat(32), server_time: rs.now, reason: t.reason, ...t.expect };
      expect(C.rulingErrors(g), t.name).toBeNull();
    }
  });

  it("spec 1.1: rules in words and the checks file", () => {
    const w = c.rule_words;
    for (const t of w.conditions) expect(W.conditionWords(t.condition), t.name ?? t.expect).toBe(t.expect);
    const v3 = c.rule_states.rule_sets.v3;
    for (const t of w.rules) {
      const doc = { ...v3, version: 1, prev: null, mode: "enforce", default: "allow", fail: {}, addresses: { hosts: [], cidrs: [] }, approved: null, rules: [t.rule] };
      delete (doc as any).fingerprint_exceptions;
      expect(C.ruleSetErrors(doc), t.name).toBeNull();
      expect(W.ruleWords(t.rule), t.name).toBe(t.expect);
    }
    for (const t of w.rule_sets) {
      const local = "local_rules" in t;
      const words = local ? W.ruleSetWords(t.local_rules.rules, t.local_rules.hash, true) : W.ruleSetWords(t.rule_set.rules, t.rule_set.hash, false);
      expect(plain(words), t.name).toEqual(plain(t.expect.words));
      expect(W.ruleSetLines(words), t.name).toEqual(t.expect.lines);
    }
    const f = c.checks_files;
    for (const t of f.valid) {
      expect(C.checksFileErrors(t.file), t.name).toBeNull();
      for (const [name, want] of Object.entries<any>(t.expect.tools)) {
        const s = C.toolSettings(t.file, name);
        expect({ strict: s.strict, fail: s.fail, mode: s.mode, disclose: s.disclose }, `${t.name} ${name}`).toEqual(plain(want));
      }
      expect(t.file.rules === null ? null : hashJson(t.file.rules), t.name).toBe(t.expect.local_rules_hash);
    }
    for (const t of f.invalid) expect(C.checksFileErrors(t.file), t.name).not.toBeNull();
  });

  it("the checks file schema", () => {
    const good = C.defaultChecksFile();
    expect(C.checksFileErrors(good)).toBeNull();
    const bad = [
      { ...good, extra: 1 },
      { ...good, mode: "audit" },
      { ...good, checks: { ...good.checks, proxy: true } },
      { ...good, tools: { pay: { strict: true, fail: "maybe" } } },
      { ...good, tools: { pay: { strict: true, disclose: ["amount"] } } },
      { ...good, addresses: { hosts: [], cidrs: [] } },
      { ...good, rules: { default: "allow", rules: [{ id: "r", about: "", action: "block", tools: null, agents: null, when: [], limit: { calls: 1, seconds: 1, per: "agent" } }] } },
      { ...good, ruling_timeout_ms: 0 },
      { ...good, ruling_timeout_ms: 60_001 },
    ];
    for (const b of bad) expect(C.checksFileErrors(b), JSON.stringify(b)).not.toBeNull();
    expect(C.checksFileErrors(bad[6])).toContain("limit");
  });
});
