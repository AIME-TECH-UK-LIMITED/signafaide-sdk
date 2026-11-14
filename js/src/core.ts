/**
 * `signafaide/core`: the protocol without local state. No Node APIs, so it runs in
 * browsers and edge runtimes: JCS, hashes, Ed25519 keys and signatures, Merkle
 * proofs, envelopes, the HTTP client and the §7 pack verifier.
 */

export { JsonNumber, assertPortableNumbers, canonicalize, canonicalBytes, parseJson } from "./jcs.js";
export { SigningKey, auditPath, b64url, b64urlDecode, checkContent, contentHash, hashJson, keyId, leafHash, merkleRoot, newSalt, sha256Hex, signedMessage, verifyInclusion, verifySig, type Domain } from "./crypto.js";
export {
  AGENT_RE,
  agentName,
  draftErrors,
  envelopeErrors,
  keyEntryErrors,
  makeDraft,
  makeRecord,
  manifestEntry,
  manifestErrors,
  registration,
  signDraft,
  now,
  clampTime,
  withWallTime,
  receiptErrors,
  recordErrors,
  recordHash,
  validProjectId,
  validTime,
  wireRecord,
  type AgentKeyEntry,
  type Envelope,
  type Kind,
  type Receipt,
  type RecordFields,
  type SignedRecord,
} from "./records.js";
export { Client, DEFAULT_URL, SignafaideError, fetchJson } from "./http.js";
export { MAX_NODES, MAX_PROOF_BYTES, blockAttestations, otsStatus, parseOts } from "./ots.js";
export { checkHeader, rootsFromVector, target, type BlockHeader, type BlockRoots } from "./timestamps.js";
export {
  ANCHOR_WINDOW_MS,
  CHECKS,
  KeysRequired,
  MAX_ROUND,
  NOT_INDEPENDENT,
  Report,
  checkRoundTime,
  contentFromText,
  countsText,
  exportStatement,
  isLoopbackUrl,
  loadDrandVerifier,
  recordsHash,
  resultLine,
  scopeText,
  parseAgentKeys,
  parseHeadFile,
  parseServiceKeys,
  serviceKeysHash,
  timestampHeights,
  verifyLocalState,
  verifyPack,
  type Check,
  type CheckId,
  type DrandBeacon,
  type DrandVerifier,
  type KeyDoc,
  type KeySource,
  type PackFilter,
  type PackOptions,
  type SignedHeadDoc,
  type Status,
} from "./verifier.js";
export { HEADER, clientHeader, detectAgent, telemetryEnabled } from "./telemetry.js";
export { VERSION } from "./version.js";
