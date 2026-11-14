"""Envelopes and signed records (SPEC §2)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from .crypto import HEX64, SALT_RE, SigningKey, b64url, b64url_decode, content_hash, hash_json, key_id, new_salt, verify_sig
from .jcs import assert_portable_numbers

KINDS = ("decision", "outcome", "note")
ENVELOPE_FIELDS = ("v", "kind", "project", "env", "agent", "seq", "prev", "time", "name", "content_hash", "ref")
#: A draft (§8) is an envelope without project and env, written before the project is known.
DRAFT_FIELDS = ("v", "kind", "agent", "seq", "prev", "time", "name", "content_hash", "ref")
ENVS = ("test", "live")
API_KEY_RE = re.compile(r"\Asfa_(test|live)_[0-9A-Za-z]{32}\Z")
AGENT_KEYS_FORMAT = "signafaide-agent-keys/1"
#: A record's time may be at most this far after its batch's server_time (§2.2).
MAX_CLOCK_SKEW_MS = 300_000
AGENT_RE = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
TIME_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\Z")
KEY_ID_RE = re.compile(r"\A[0-9a-f]{16}\Z")
PROJECT_RE = re.compile(r"\Aprj_[0-7][0-9A-HJKMNP-TV-Z]{25}\Z")
RECEIPT_FIELDS = {"record_hash", "index", "proof", "batch", "batch_hash", "batch_sig", "service_key_id", "head", "head_sig"}
BATCH_FIELDS = {"v", "project", "env", "seq", "prev", "root", "size", "server_time", "drand"}
HEAD_FIELDS = {"project", "env", "agent", "seq", "record_hash", "server_time"}
DRAND_FIELDS = {"chain", "round", "randomness", "signature"}


def now() -> str:
    """Current time as RFC 3339 UTC with milliseconds."""
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def clamp_time(wall: str, prev: Optional[str] = None, valid_from: Optional[str] = None) -> "tuple[str, bool]":
    """§2.2 monotonic time: the machine's clock (*wall*), raised to the previous record's time in
    the chain and to the signing key's valid_from when it reads earlier (an NTP step back, a VM
    resumed). Returns (time, raised). When raised, the SDK keeps *wall* in the content's
    ``meta.wall_time``. A chain written this way never goes back in time."""
    t = wall
    for f in (prev, valid_from):
        if f and _valid_time(f) and f > t:  # protocol times sort as text
            t = f
    return t, t != wall


def with_wall_time(content: dict, wall: str) -> dict:
    """*content* with the clock's own reading kept in ``meta.wall_time`` (when the record's time was raised)."""
    meta = content.get("meta")
    if meta is None:
        return {**content, "meta": {"wall_time": wall}}
    if isinstance(meta, dict):
        return {**content, "meta": {**meta, "wall_time": wall}}
    return {**content, "wall_time": wall}


def parse_time(s: str) -> datetime:
    if not isinstance(s, str) or not TIME_RE.match(s):
        raise ValueError(f"time {s!r} is not RFC 3339 UTC with milliseconds")
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def agent_name(raw: str) -> str:
    """Turn a folder or free-form name into a valid agent id."""
    s = re.sub(r"[^a-z0-9._-]+", "-", raw.strip().lower())
    s = re.sub(r"^[^a-z0-9]+", "", s)[:64].rstrip("-")
    return s or "agent"


def envelope_errors(env: Any, fields: tuple = ENVELOPE_FIELDS) -> list:
    """Schema problems with an envelope; empty when valid (§2.2)."""
    if not isinstance(env, dict):
        return ["envelope is not an object"]
    errs = []
    missing = [f for f in fields if f not in env]
    extra = sorted(set(env) - set(fields))
    if missing:
        errs.append("missing " + ", ".join(missing))
    if extra:
        errs.append("unknown field " + ", ".join(extra))
    if missing:
        return errs

    def is_int(x: Any) -> bool:
        return isinstance(x, int) and not isinstance(x, bool)

    if env["v"] != 1 or not is_int(env["v"]):
        errs.append("v must be 1")
    if env["kind"] not in KINDS:
        errs.append("kind must be decision, outcome or note")
    if "project" in fields and not valid_project_id(env["project"]):
        errs.append("project must be prj_ followed by a 26-character ULID")
    if "env" in fields and env["env"] not in ENVS:
        errs.append("env must be test or live")
    if not isinstance(env["agent"], str) or not AGENT_RE.match(env["agent"]):
        errs.append("agent does not match ^[a-z0-9][a-z0-9._-]{0,63}$")
    seq = env["seq"]
    if not is_int(seq) or not 1 <= seq <= 2**53 - 1:
        errs.append("seq must be an integer from 1 to 2^53-1")
    elif seq == 1 and env["prev"] is not None:
        errs.append("prev must be null when seq = 1")
    elif seq > 1 and not (isinstance(env["prev"], str) and HEX64.match(env["prev"])):
        errs.append("prev must be a record hash when seq > 1")
    try:
        parse_time(env["time"])
    except ValueError as e:
        errs.append(str(e))
    name = env["name"]
    if not isinstance(name, str) or not 1 <= len(name) <= 128:
        errs.append("name must be 1 to 128 characters")
    if not isinstance(env["content_hash"], str) or not HEX64.match(env["content_hash"]):
        errs.append("content_hash must be 64 lowercase hex")
    if env["kind"] == "outcome":
        if not (isinstance(env["ref"], str) and HEX64.match(env["ref"])):
            errs.append("ref must be the decision's record hash for an outcome")
    elif env["ref"] is not None:
        errs.append("ref must be null unless kind is outcome")
    return errs


def valid_project_id(s: Any) -> bool:
    """``prj_`` + a 26-character ULID in Crockford base32."""
    return isinstance(s, str) and bool(PROJECT_RE.match(s))


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _is_hex(x: Any) -> bool:
    return isinstance(x, str) and bool(HEX64.match(x))


def _valid_time(x: Any) -> bool:
    try:
        parse_time(x)
        return True
    except ValueError:
        return False


def receipt_errors(rc: Any) -> list:
    """Schema problems with a receipt (§3.4): exact fields and types; signatures
    are only checked to be strings (their validity is checks 6 and 8)."""
    if not isinstance(rc, dict) or set(rc) != RECEIPT_FIELDS:
        return ["receipt fields are " + ", ".join(sorted(RECEIPT_FIELDS))]
    b, h = rc["batch"], rc["head"]
    errs = []
    if not (_is_hex(rc["record_hash"]) and _is_hex(rc["batch_hash"]) and _is_int(rc["index"]) and rc["index"] >= 0):
        errs.append("receipt record_hash, batch_hash or index is invalid")
    if not (isinstance(rc["proof"], list) and all(_is_hex(p) for p in rc["proof"])):
        errs.append("receipt proof must be a list of hashes")
    if not all(isinstance(rc[k], str) for k in ("batch_sig", "head_sig", "service_key_id")):
        errs.append("receipt batch_sig, head_sig and service_key_id are strings")
    if not isinstance(b, dict) or set(b) != BATCH_FIELDS:
        errs.append("batch fields are " + ", ".join(sorted(BATCH_FIELDS)))
    elif not (
        b["v"] == 1 and _is_int(b["v"]) and valid_project_id(b["project"]) and b["env"] in ("test", "live")
        and _is_int(b["seq"]) and b["seq"] >= 1 and (b["prev"] is None or _is_hex(b["prev"])) and _is_hex(b["root"])
        and _is_int(b["size"]) and b["size"] >= 1 and _valid_time(b["server_time"])
    ):
        errs.append("batch has an invalid value")
    elif b["drand"] is not None and not (
        isinstance(b["drand"], dict) and set(b["drand"]) == DRAND_FIELDS and _is_int(b["drand"]["round"])
        and all(isinstance(b["drand"][k], str) for k in ("chain", "randomness", "signature"))
    ):
        errs.append("batch drand must be null or {chain, round, randomness, signature}")
    if not isinstance(h, dict) or set(h) != HEAD_FIELDS:
        errs.append("head fields are " + ", ".join(sorted(HEAD_FIELDS)))
    elif not (
        valid_project_id(h["project"]) and h["env"] in ("test", "live") and isinstance(h["agent"], str) and AGENT_RE.match(h["agent"])
        and _is_int(h["seq"]) and _is_hex(h["record_hash"]) and _valid_time(h["server_time"])
    ):
        errs.append("head has an invalid value")
    return errs


def record_errors(rec: Any) -> list:
    """Schema problems with a signed record (§2.3); ``receipt`` is allowed."""
    if not isinstance(rec, dict):
        return ["record is not an object"]
    errs = envelope_errors(rec.get("envelope"))
    extra = sorted(set(rec) - {"envelope", "key_id", "sig", "content", "salt", "receipt"})
    if extra:
        errs.append("unknown record field " + ", ".join(extra))
    if not isinstance(rec.get("key_id"), str) or not KEY_ID_RE.match(rec["key_id"]):
        errs.append("key_id must be 16 lowercase hex")
    try:
        if len(b64url_decode(rec.get("sig"))) != 64:
            raise ValueError
    except (ValueError, TypeError):
        errs.append("sig must be a base64url Ed25519 signature")
    if "content" in rec and not isinstance(rec["content"], dict):
        errs.append("content must be a JSON object")
    if "salt" in rec and not (isinstance(rec["salt"], str) and SALT_RE.match(rec["salt"])):
        errs.append("salt must be 32 lowercase hex")
    return errs


def make_record(
    key: SigningKey,
    *,
    kind: str,
    project: str,
    env: str,
    agent: str,
    seq: int,
    prev: Optional[str],
    name: str,
    content: dict,
    ref: Optional[str] = None,
    time: Optional[str] = None,
    salt: Optional[str] = None,
) -> dict:
    """Build and sign ``{envelope, key_id, sig, content, salt}``: the content hash is salted with
    ``salt``, a fresh random one unless given (SPEC §2.1). Raises ValueError on a bad envelope or
    on content numbers other implementations could not re-read (SPEC §1)."""
    assert_portable_numbers(content)
    salt = salt or new_salt()
    envelope = {
        "v": 1,
        "kind": kind,
        "project": project,
        "env": env,
        "agent": agent,
        "seq": seq,
        "prev": prev,
        "time": time or now(),
        "name": name,
        "content_hash": content_hash(content, salt),
        "ref": ref,
    }
    errs = envelope_errors(envelope)
    if errs:
        raise ValueError("invalid record: " + "; ".join(errs))
    return {"envelope": envelope, "key_id": key.key_id, "sig": key.sign("record", hash_json(envelope)), "content": content, "salt": salt}


def make_draft(key: SigningKey, *, kind: str, agent: str, seq: int, prev: Optional[str], name: str, content: dict, ref: Optional[str] = None,
               time: Optional[str] = None, store_content: bool = False, salt: Optional[str] = None) -> dict:
    """A draft (§8) for a chain whose project is not known yet (no API key, or the key's
    project not learned): the envelope without project and env, signed by the agent's key
    over domain ``draft``, so a local chain verifies before anything is sent.
    ``record_hash`` of a draft is its draft hash."""
    assert_portable_numbers(content)
    salt = salt or new_salt()
    d = {"v": 1, "kind": kind, "agent": agent, "seq": seq, "prev": prev, "time": time or now(), "name": name, "content_hash": content_hash(content, salt), "ref": ref}
    errs = envelope_errors(d, DRAFT_FIELDS)
    if errs:
        raise ValueError("invalid record: " + "; ".join(errs))
    return {"draft": True, "envelope": d, "key_id": key.key_id, "sig": key.sign("draft", hash_json(d)), "content": content, "salt": salt, "store_content": store_content}


def draft_errors(rec: Any) -> list:
    """Schema problems with a draft line (§8); empty when valid."""
    if not isinstance(rec, dict):
        return ["draft is not an object"]
    errs = envelope_errors(rec.get("envelope"), DRAFT_FIELDS)
    extra = sorted(set(rec) - {"draft", "envelope", "key_id", "sig", "content", "salt", "store_content"})
    if extra:
        errs.append("unknown draft field " + ", ".join(extra))
    if rec.get("draft") is not True:
        errs.append("draft must be true")
    if not isinstance(rec.get("key_id"), str) or not KEY_ID_RE.match(rec["key_id"]):
        errs.append("key_id must be 16 lowercase hex (an unsigned draft from an older SDK cannot be verified)")
    try:
        if len(b64url_decode(rec.get("sig"))) != 64:
            raise ValueError
    except (ValueError, TypeError):
        errs.append("sig must be a base64url Ed25519 signature")
    if "content" in rec and not isinstance(rec["content"], dict):
        errs.append("content must be a JSON object")
    if "salt" in rec and not (isinstance(rec["salt"], str) and SALT_RE.match(rec["salt"])):
        errs.append("salt must be 32 lowercase hex")
    if "store_content" in rec and not isinstance(rec["store_content"], bool):
        errs.append("store_content must be true or false")
    return errs


def sign_draft(key: SigningKey, draft: dict, *, project: str, env: str, prev: Optional[str], ref: Optional[str], seq: Optional[int] = None) -> dict:
    """The signed record for a draft once its project is known (§8)."""
    d = draft["envelope"]
    return make_record(key, kind=d["kind"], project=project, env=env, agent=d["agent"], seq=d["seq"] if seq is None else seq, prev=prev, name=d["name"],
                       content=draft["content"], ref=ref, time=d["time"], salt=draft.get("salt"))


# --- keys (§2.4, §2.5) ------------------------------------------------------------


def key_entry_errors(k: Any, agent: bool = False) -> list:
    """A service key (§5) or, with ``agent``, a pack's agent key: exact fields, valid times."""
    fields = {"key_id", "public_key", "valid_from", "valid_to"} | ({"agent"} if agent else set())
    if not isinstance(k, dict) or set(k) != fields:
        return ["key fields are " + ", ".join(sorted(fields))]
    if not all(isinstance(k[f], str) for f in fields - {"valid_to"}):
        return ["key fields must be strings"]
    if not _valid_time(k["valid_from"]):
        return [f"key {k['key_id']}: valid_from is not a time"]
    if k["valid_to"] is not None and not _valid_time(k["valid_to"]):
        return [f"key {k['key_id']}: valid_to is not null or a time"]
    return []


def registration(project: str, env: str, agent: str, public_key: str, valid_from: str) -> dict:
    return {"project": project, "env": env, "agent": agent, "public_key": public_key, "valid_from": valid_from}


def manifest_entry(agent: str, key: SigningKey, valid_from: str, valid_to: Optional[str] = None) -> dict:
    """A self-signed agent-key manifest entry (§2.5); ``valid_to`` is when a retired key was retired."""
    e = {"agent": agent, "key_id": key.key_id, "public_key": b64url(key.public_key), "valid_from": valid_from, "valid_to": valid_to}
    return {**e, "sig": key.sign("agent_key", hash_json(e))}


def manifest_errors(doc: Any) -> list:
    """Problems with an agent-key manifest (§2.5), self-signatures included."""
    if not isinstance(doc, dict) or set(doc) != {"format", "keys"} or not isinstance(doc["keys"], list):
        return ['agent keys must be {"format": "signafaide-agent-keys/1", "keys": [...]}']
    if doc["format"] != AGENT_KEYS_FORMAT:
        return [f"format is '{doc['format']}', expected '{AGENT_KEYS_FORMAT}'"]
    for e in doc["keys"]:
        if not isinstance(e, dict) or set(e) != {"agent", "key_id", "public_key", "valid_from", "valid_to", "sig"} or not all(
            isinstance(v, str) for k, v in e.items() if k != "valid_to"
        ) or not (e["valid_to"] is None or isinstance(e["valid_to"], str)):
            return ["each agent key is {agent, key_id, public_key, valid_from, valid_to, sig}"]
        if not AGENT_RE.match(e["agent"]):
            return [f"agent {e['agent']} is not a valid agent name"]
        try:
            if key_id(b64url_decode(e["public_key"])) != e["key_id"] or len(b64url_decode(e["public_key"])) != 32:
                return [f"key_id {e['key_id']} does not match its public key"]
        except ValueError:
            return [f"key {e['key_id']}: public key is not base64url"]
        if not _valid_time(e["valid_from"]):
            return [f"key {e['key_id']}: valid_from is not a time"]
        if e["valid_to"] is not None and not _valid_time(e["valid_to"]):
            return [f"key {e['key_id']}: valid_to is not null or a time"]
        signed = {k: e[k] for k in ("agent", "key_id", "public_key", "valid_from", "valid_to")}
        if not verify_sig(e["public_key"], "agent_key", hash_json(signed), e["sig"]):
            return [f"the self-signature of key {e['key_id']} for {e['agent']} does not verify"]
    return []


def record_hash(rec: dict) -> str:
    return hash_json(rec["envelope"])
