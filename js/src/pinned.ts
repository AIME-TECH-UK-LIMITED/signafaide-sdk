// The keys document pinned in this release (the package's service-keys.json, spec/service-keys.json):
// the default witness's keys and the revocations every verifier of this SDK applies (spec §5, §7).
import PINNED from "../service-keys.json";

/** The pinned document, read when used. Tests replace `doc` to pin revocations (never in use). */
export const pinned: { doc: unknown } = { doc: PINNED };
