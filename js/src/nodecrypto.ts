/** Plugs OpenSSL (node:crypto) into the protocol's hashes and Ed25519 checks. Node only;
 * imported by the SDK's Node entry points, never by `signafaide/core`. */

import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { useNativeCrypto } from "./crypto.js";

const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");
const keys = new Map<string, KeyObject | null>();

function publicKey(raw: Uint8Array): KeyObject | null {
  const id = Buffer.from(raw).toString("hex");
  let k = keys.get(id);
  if (k === undefined) {
    try {
      k = createPublicKey({ key: Buffer.concat([SPKI_ED25519, raw]), format: "der", type: "spki" });
    } catch {
      k = null; // not a point on the curve: no signature verifies with it
    }
    if (keys.size > 10_000) keys.clear();
    keys.set(id, k);
  }
  return k;
}

/** Install OpenSSL for hashes and Ed25519 checks (idempotent). */
export function installNodeCrypto(): void {
  useNativeCrypto({
  sha256: (data) => new Uint8Array(createHash("sha256").update(data).digest()),
  verify: (pk, message, sig) => {
    const k = publicKey(pk);
    if (!k) return false;
    try {
      return verify(null, message, k, sig);
    } catch {
      return false;
    }
  },
});
}
