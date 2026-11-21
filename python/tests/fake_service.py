"""An in-process fake of the signafAIde service (SPEC §3, §5, §6) for tests.

It really validates and signs: records are checked (schema, agent key,
signature, chain, content), batched into an RFC 6962 tree and covered by
batch and head signatures from a service key.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from signafaide.crypto import (
    SigningKey,
    audit_path,
    b64url,
    b64url_decode,
    content_hash,
    hash_json,
    key_id,
    merkle_root,
    verify_sig,
)
from signafaide.records import now, parse_time, record_errors, record_hash, registration


def err(status, code, message, **extra):
    return status, {"error": {"code": code, "message": message, "docs": f"https://docs.example/errors#{code}", **extra}}


def _rfc3339(t: float) -> str:
    """Unix seconds as RFC 3339 UTC with milliseconds."""
    ms = int(round(t * 1000))
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms // 1000)) + f".{ms % 1000:03d}Z"


class FakeService:
    def __init__(self):
        self.key = SigningKey.generate()
        self.key_doc = {
            "key_id": self.key.key_id,
            "public_key": b64url(self.key.public_key),
            "valid_from": "2020-01-01T00:00:00.000Z",
            "valid_to": None,
        }
        self.extra_keys = []  # more keys served after key_doc (a rotation in progress)
        self.revoked = None  # the served `revoked` list (§5), when set
        self.list_reset_seq = 0  # a client behind this seq gets the snapshot with `reset` (§11.2)
        self.projects = {}  # api_key -> project
        self.calls = []
        self.fail = None  # (status, code, message) returned once for the next /v1/records
        self.fail_always = None  # returned for every /v1/records until cleared (a refusal that persists)
        self.quota = None  # monthly allowance per project; None: unlimited
        self.hang = 0.0  # seconds to wait before answering any request (a slow or hanging witness)
        self.lock = threading.Lock()
        self.sandbox_n = 0
        self.sandbox_days = (
            30  # days an unclaimed sandbox is kept; None: a witness that sends no expires_at (an older one)
        )
        self.registrations = []
        #: Tool-call checks (§3.5, §10, §11): the signed rule set versions per project, the shared
        #: list's signed updates, and how the witness answers a strict decision.
        self.rule_items = {}  # project -> [{rules, sig, service_key_id}], oldest first
        self.list_updates = []  # [{list, sig, service_key_id}]
        self.list_entries = []
        self.served_version = None  # GET /v1/rules answers this version, when set (rulings use the newest)
        self.rules_fetches = []  # (version query, If-None-Match) of every GET /v1/rules
        self.no_ruling = False  # a witness that does not rule: receipts without a ruling
        self.ruling_error = None  # e.g. "rules_unavailable": the receipt says why there is no ruling
        self.disclosed = {}  # record_hash -> (disclosed, disclosed_salt) the witness received
        self.req_headers = {}
        self.client_ids = []  # X-Signafaide-Client of every request
        self.events = []
        #: Spec 1.1: device sign-ins, person sessions, how each version was published, auditor links.
        self.devices = {}  # device_code -> {"user_code", "status"}
        self.sessions = {}  # session -> {"email", "org", "roles"}
        #: A console page: POST /v1/rules with a session answers 202 {"confirm_in_console": <it>}.
        self.confirm_in_console = None
        self.published = []
        self.auditor_links = []
        self.auditor_links_off = False
        #: The plan's longest auditor link (plan_required above it), whether the refusal says it
        #: as max_days, and a witness of before agent_keys and head (bad_request when sent).
        self.auditor_max_days = None
        self.auditor_max_in_body = True
        self.auditor_links_no_keys = False
        #: As the service: a repeat for the same agent, tool and start while its link is open
        #: answers that link again (200, ``reused: true``), whatever ``days`` asks.
        self.auditor_reuse = False
        self.pending_roles = {}
        handler = self._handler()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def cleanup(self):
        """The daily cleanup: delete every unclaimed sandbox whose time has passed; their keys are then refused."""
        from signafaide import _claim

        for key, prj in list(self.projects.items()):
            if prj.get("expires_at") and not prj.get("claimed") and _claim.days_left(prj["expires_at"]) == 0:
                del self.projects[key]

    def add_project(self, api_key, env="test"):
        self.n_projects = getattr(self, "n_projects", 0) + 1
        prj = {
            "project": f"prj_01JC{self.n_projects:022d}",
            "env": env,
            "agents": {},
            "heads": {},
            "records": {},
            "batches": [],
            "used": 0,
        }
        self.projects[api_key] = prj
        return prj

    # --- routing --------------------------------------------------------------

    def route(self, method, path, query, body, auth):
        self.calls.append((method, path))
        if method == "GET" and path == "/healthz":
            return 200, "ok"
        if method == "GET" and path == "/.well-known/signafaide-keys.json":
            return 200, {
                "keys": [self.key_doc, *self.extra_keys],
                **({} if self.revoked is None else {"revoked": self.revoked}),
            }
        if method == "POST" and path == "/v1/sandbox":
            self.sandbox_n += 1
            key = "sfa_test_" + f"{self.sandbox_n:032d}"
            prj = self.add_project(key)
            if self.sandbox_days is not None:
                prj["expires_at"] = _rfc3339(time.time() + self.sandbox_days * 86_400)
            return 200, {
                "project": prj["project"],
                "api_key": key,
                "claim_url": f"{self.url}/app/claim/{self.sandbox_n}",
                "free_quota": 1000,
                **({"expires_at": prj["expires_at"]} if prj.get("expires_at") else {}),
                "terms_url": f"{self.url}/legal/terms",
                "privacy_url": f"{self.url}/legal/privacy",
            }
        if method == "POST" and path == "/v1/events":
            self.events.append(body.get("name"))
            return 200, {}
        if method == "POST" and path == "/v1/device/code":
            code = f"dev{len(self.devices) + 1:040d}"
            self.devices[code] = {"user_code": "BCDF-GHJK", "status": "pending"}
            return 200, {
                "device_code": code,
                "user_code": "BCDF-GHJK",
                "verification_uri": f"{self.url}/app/device",
                "verification_uri_complete": f"{self.url}/app/device?code=BCDF-GHJK",
                "expires_in": 600,
                "interval": 5,
            }
        if method == "POST" and path == "/v1/device/token":
            d = self.devices.get((body or {}).get("device_code"))
            if d is None or d["status"] == "used":
                return 200, {"status": "expired"}
            if d["status"] == "approved":
                d["status"] = "used"
                session = f"sfa_user_{len(self.sessions) + 1:032d}"
                self.sessions[session] = {
                    "email": "owner@example.test",
                    "org": "Example Org",
                    "roles": self.pending_roles,
                }
                return 200, {
                    "status": "approved",
                    "session": session,
                    "expires_at": _rfc3339(time.time() + 12 * 3600),
                    "person": {"email": "owner@example.test"},
                    "organisation": {"name": "Example Org"},
                }
            return 200, {"status": d["status"]}
        bearer = (auth or "").removeprefix("Bearer ")
        person = self.sessions.get(bearer)
        if person is not None:
            if method == "GET" and path == "/v1/session":
                # §6: the projects the person can see, with their role in each (owner, admin or developer).
                projects = [
                    {"project": p["project"], "name": "Claims", "env": p["env"], "role": person["roles"][p["project"]]}
                    for p in self.projects.values()
                    if p["project"] in person["roles"]
                ]
                return 200, {
                    "person": {"email": person["email"]},
                    "organisation": {"name": person["org"]},
                    "expires_at": _rfc3339(time.time() + 3600),
                    "projects": projects,
                }
            if method == "DELETE" and path == "/v1/session":
                del self.sessions[bearer]
                return 204, ""
            if method == "POST" and path == "/v1/rules":
                target = next(
                    (
                        k
                        for k, p in self.projects.items()
                        if p["project"] == body.get("project") and p["env"] == body.get("env")
                    ),
                    None,
                )
                if target is None:
                    return err(404, "not_found", "No such project.")
                if self.confirm_in_console is not None:
                    # §6: loosening a live project's rules from the command line waits for a person in the console.
                    return 202, {"confirm_in_console": self.confirm_in_console}
                return self._publish_draft(target, body, "session", person["email"])
            return err(401, "invalid_key", "A person session is not an API key.")
        prj = self.projects.get(bearer)
        if prj is None:
            return err(401, "invalid_key", "The API key is not valid; run `signafaide init` for a new sandbox key.")
        if method == "POST" and path == "/v1/rules":
            # An API key publishes only into its own sandbox while it is unclaimed (§6).
            if body.get("project") != prj["project"] or body.get("env") != prj["env"]:
                return err(401, "invalid_key", "An API key cannot publish rules; sign in with `signafaide login`.")
            if prj["env"] != "test" or prj.get("claimed"):
                # As the service: where a person adds the rules instead, the project's Tools page.
                return err(
                    401,
                    "invalid_key",
                    "An API key publishes rules only into its own sandbox while nobody has claimed it.",
                    add_in_console=f"{self.url}/app/p/{prj['project']}/{prj['env']}/tools",
                )
            return self._publish_draft(bearer, body, "sandbox_key", None)
        if method == "POST" and path == "/v1/auditor-links":
            if self.auditor_links_off:
                return err(404, "not_found", "No such endpoint.")
            if self.auditor_max_days is not None and body.get("days", 0) > self.auditor_max_days:
                extra = {"max_days": self.auditor_max_days} if self.auditor_max_in_body else {}
                return err(
                    402,
                    "plan_required",
                    f"An auditor link of an unclaimed sandbox expires within {self.auditor_max_days} days: ask for fewer days, "
                    "or claim the sandbox in the console.",
                    **extra,
                )
            if self.auditor_links_no_keys and ("agent_keys" in body or "head" in body):
                return err(400, "bad_request", "Unknown field agent_keys.")
            if self.auditor_reuse:
                for i, b in enumerate(self.auditor_links):
                    if (
                        b.get("agent") == body.get("agent")
                        and b.get("tool") == body.get("tool")
                        and b.get("from") == body.get("from")
                    ):
                        return 200, {
                            "url": f"{self.url}/audit/aud_{i + 1}",
                            "expires_at": _rfc3339(b["at"] + b.get("days", 30) * 86_400),
                            "reused": True,
                            "agent_keys": True,
                        }
                body["at"] = time.time()
            self.auditor_links.append(body)
            return 201, {
                "url": f"{self.url}/audit/aud_{len(self.auditor_links)}",
                "expires_at": _rfc3339(time.time() + body.get("days", 30) * 86_400),
                **({"agent_keys": True} if "agent_keys" in body else {}),
            }
        if method == "GET" and path == "/v1/project":
            # As the service: expires_at only while the sandbox is unclaimed.
            return 200, {
                "project": prj["project"],
                "env": prj["env"],
                "claimed": bool(prj.get("claimed")),
                "name": prj.get("name"),
                **({"expires_at": prj["expires_at"]} if prj.get("expires_at") and not prj.get("claimed") else {}),
            }
        if method == "POST" and path == "/v1/agents":
            pk = body["public_key"]
            kid = key_id(b64url_decode(pk))
            if any(kid in keys for name, keys in prj["agents"].items() if name != body["name"]):
                return err(
                    400, "invalid_record", "This key is registered to another agent; generate a new key for this agent."
                )
            if parse_time(body["valid_from"]).timestamp() > time.time() + 60:
                return err(
                    400,
                    "invalid_record",
                    f"valid_from {body['valid_from']} is ahead of the service clock ({now()}): the client's clock is ahead.",
                )
            h = hash_json(registration(prj["project"], prj["env"], body["name"], pk, body.get("valid_from") or ""))
            if not verify_sig(pk, "register", h, body.get("proof") or ""):
                return err(
                    400,
                    "bad_signature",
                    "proof must be the new key's signature over the registration (domain register).",
                )
            ag = prj["agents"].setdefault(body["name"], {})
            active = {k: v for k, v in ag.items() if v["valid_to"] is None and k != kid}
            if active and kid not in ag:
                rot = body.get("rotation") or {}
                if rot.get("key_id") not in active or not verify_sig(
                    active[rot["key_id"]]["public_key"], "rotate", h, rot.get("sig") or ""
                ):
                    return err(
                        400,
                        "bad_signature",
                        "This agent already has an active key: sign the registration with it (rotation), or revoke it in the console first.",
                    )
                # A rotation retires the key that signed it (§2.4), after its newest record.
                newest = max(
                    (r["envelope"]["time"] for r, _ in prj["records"].values() if r["key_id"] == rot["key_id"]),
                    default=None,
                )
                t = now()
                if newest and newest >= t:
                    from signafaide.verifier import _epoch_ms, _fmt

                    t = _fmt(_epoch_ms(newest) + 1)
                active[rot["key_id"]]["valid_to"] = t
            self.registrations.append(body)
            ag.setdefault(
                kid,
                {
                    "agent": body["name"],
                    "key_id": kid,
                    "public_key": pk,
                    "valid_from": body["valid_from"],
                    "valid_to": None,
                },
            )
            retired = [
                {"key_id": k, "valid_to": v["valid_to"]} for k, v in sorted(ag.items()) if v["valid_to"] is not None
            ]
            return 200, {"agent": body["name"], "key_id": kid, "retired": retired}
        if method == "POST" and path == "/v1/records":
            if self.fail_always:
                return self.fail_always
            if self.fail:
                f, self.fail = self.fail, None
                return f
            with self.lock:
                return self.submit(prj, body.get("records") or [])
        if method == "GET" and path.startswith("/v1/heads/"):
            agent = path.rsplit("/", 1)[1]
            if agent in prj["heads"]:
                return 200, prj["heads"][agent]
            if getattr(self, "heads_unknown_agent", False) and agent not in prj["agents"]:
                # A witness before 0.1.4 answered 400 for an agent that was never registered.
                return err(
                    400,
                    "unknown_agent",
                    f"Agent '{agent}' is not registered in this project and env: call POST /v1/agents first.",
                )
            return err(404, "not_found", "This agent has no records.")
        if method == "GET" and path.startswith("/v1/records/"):
            got = prj["records"].get(path.rsplit("/", 1)[1])
            return (
                (200, {"record": got[0], "receipt": got[1], "anchor": None})
                if got
                else err(404, "not_found", "No record with this hash in this project.")
            )
        if method == "GET" and path == "/v1/usage":
            return 200, {"period": "2026-11", "used": prj["used"], "quota": 1000, "plan": prj.get("plan", "free")}
        if method == "GET" and path == "/v1/export":
            return 200, self.export(prj, query.get("agent"), query.get("from"), query.get("to"))
        if method == "GET" and path == "/v1/rules":
            items = self.rule_items.get(prj["project"], [])
            self.rules_fetches.append((query.get("version"), self.req_headers.get("If-None-Match")))
            if not items:
                return 200, {"rules": None}
            wanted = query.get("version")
            if wanted is None and self.served_version is not None:
                wanted = str(self.served_version)  # a witness that keeps answering an older version
            item = (
                items[-1] if wanted is None else next((i for i in items if str(i["rules"]["version"]) == wanted), None)
            )
            if item is None:
                return err(404, "not_found", "No such version.")
            if self.req_headers.get("If-None-Match") == f'"{hash_json(item["rules"])}"':
                return 304, ""
            return 200, item
        if method == "GET" and path == "/v1/fingerprints":
            since = query.get("since")
            if since is None:
                return 200, {"snapshot": self.list_snapshot(), "updates": []}
            if int(since) < self.list_reset_seq:
                return 200, {"reset": True, "snapshot": self.list_snapshot(), "updates": []}
            return 200, {
                "snapshot": None,
                "updates": [u for u in self.list_updates if u["list"]["seq"] > int(since)][:1000],
            }
        if method == "POST" and path == "/v1/experiments":
            self.experiments = getattr(self, "experiments", []) + [body]
            return 201, {
                "id": f"exp_{len(self.experiments)}",
                "n": len(body["rows"]),
                "url": f"{self.url}/app/experiments/{len(self.experiments)}",
            }
        return err(404, "not_found", "No such endpoint.")

    def submit(self, prj, records):
        if not records or len(records) > 1000:
            return err(400, "invalid_record", "Send 1 to 1000 records.")
        tips = {a: (h["head"]["seq"], h["head"]["record_hash"]) for a, h in prj["heads"].items()}
        new = []
        for r in records:
            if record_errors(r):
                return err(400, "invalid_record", "Record schema is invalid: " + "; ".join(record_errors(r)) + ".")
            h = record_hash(r)
            if h in prj["records"]:
                continue
            env = r["envelope"]
            if (env["project"], env["env"]) != (prj["project"], prj["env"]):
                return err(
                    400, "invalid_record", "envelope.project and envelope.env must be this key's project and env."
                )
            # As the real service: an unknown agent is unknown_agent; a known agent's unregistered key is bad_signature.
            keys = prj["agents"].get(env["agent"])
            if keys is None:
                return err(
                    400,
                    "unknown_agent",
                    f"agent '{env['agent']}' is not registered in this project and env; call POST /v1/agents first.",
                )
            key = keys.get(r["key_id"])
            if key is None:
                return err(
                    400,
                    "bad_signature",
                    f"key {r['key_id']} is not registered for agent '{env['agent']}'; register it with POST /v1/agents.",
                )
            if key["valid_to"] is not None:
                return err(
                    400,
                    "bad_signature",
                    f"key {r['key_id']} was retired or revoked at {key['valid_to']}; it cannot add records.",
                )
            if parse_time(env["time"]).timestamp() > time.time() + 300:
                return err(
                    400,
                    "invalid_record",
                    f"time {env['time']} is more than 300 s ahead of the service clock ({now()}); check the client clock.",
                )
            if env["time"] < key["valid_from"]:
                return err(
                    400,
                    "bad_signature",
                    f"time {env['time']} is before key {r['key_id']} was made (valid from {key['valid_from']}).",
                )
            if not verify_sig(key["public_key"], "record", h, r["sig"]):
                return err(
                    400, "bad_signature", "The record signature does not verify; sign record_hash with domain 'record'."
                )
            if ("content" in r) != ("salt" in r) or (
                "content" in r and content_hash(r["content"], r["salt"]) != env["content_hash"]
            ):
                return err(
                    400, "content_mismatch", "content does not match content_hash; send the exact content you hashed."
                )
            ch = env.get("checks") or {}
            if ("disclosed" in r) != (ch.get("disclosed_hash") is not None):
                return err(
                    400,
                    "invalid_record",
                    "disclosed and disclosed_salt come exactly when checks.disclosed_hash is set.",
                )
            if "disclosed" in r:
                from signafaide.checks import disclosed_hash

                if disclosed_hash(r["disclosed"], r["disclosed_salt"]) != ch["disclosed_hash"]:
                    return err(400, "content_mismatch", "disclosed does not hash to checks.disclosed_hash.")
                self.disclosed[h] = (r["disclosed"], r["disclosed_salt"])
            seq, last = tips.get(env["agent"], (0, None))
            if env["seq"] != seq + 1 or env["prev"] != last:
                return err(
                    409,
                    "chain_conflict",
                    "This record does not extend the service chain; the head is attached.",
                    head={"agent": env["agent"], "seq": seq, "record_hash": last},
                )
            tips[env["agent"]] = (env["seq"], h)
            new.append(r)
        if self.quota is not None and prj["used"] + len(new) > self.quota:
            return err(429, "quota_exceeded", "This sandbox's monthly allowance is used up.")
        receipts = []
        heads = []
        if new:
            hashes = [record_hash(r) for r in new]
            prev = prj["batches"][-1]["batch_hash"] if prj["batches"] else None
            batch = {
                "v": 1,
                "project": prj["project"],
                "env": prj["env"],
                "seq": len(prj["batches"]) + 1,
                "prev": prev,
                "root": merkle_root(hashes),
                "size": len(hashes),
                "server_time": now(),
                "drand": None,
            }
            bh = hash_json(batch)
            prj["batches"].append({"batch": batch, "batch_hash": bh})
            bsig = self.key.sign("batch", bh)
            for agent in sorted({r["envelope"]["agent"] for r in new}):
                seq, last = tips[agent]
                head = {
                    "project": prj["project"],
                    "env": prj["env"],
                    "agent": agent,
                    "seq": seq,
                    "record_hash": last,
                    "server_time": batch["server_time"],
                }
                sh = {"head": head, "head_sig": self.key.sign("head", hash_json(head))}
                prj["heads"][agent] = sh
                heads.append(sh)
            for i, r in enumerate(new):
                sh = prj["heads"][r["envelope"]["agent"]]
                rc = {
                    "record_hash": hashes[i],
                    "index": i,
                    "proof": audit_path(hashes, i),
                    "batch": batch,
                    "batch_hash": bh,
                    "batch_sig": bsig,
                    "service_key_id": self.key.key_id,
                    "head": sh["head"],
                    "head_sig": sh["head_sig"],
                }
                from signafaide.checks import asks_for_ruling

                if r["envelope"]["kind"] == "decision" and asks_for_ruling(r["envelope"].get("checks")):
                    if self.ruling_error:
                        rc["ruling_error"] = self.ruling_error
                    elif not self.no_ruling:
                        g = self.rule(prj, r, rc)
                        rc["ruling"], rc["ruling_sig"] = g, self.key.sign("ruling", hash_json(g))
                prj["records"][hashes[i]] = (r, rc)
                prj["used"] += 1
        for r in records:
            receipts.append(prj["records"][record_hash(r)][1])
        return 200, {"receipts": receipts, "heads": heads}

    # --- tool-call checks -----------------------------------------------------

    def publish_rules(
        self,
        api_key,
        rules,
        *,
        mode="enforce",
        default="allow",
        fail=None,
        addresses=None,
        approved=None,
        issued=None,
        set_id="rs_01JD2K8Z5X3V7N2M4K6H8G0F1A",
        fingerprint_exceptions=None,
        protect=None,
    ):
        """Publish a new rule set version for the key's project (§10)."""
        prj = self.projects[api_key]
        items = self.rule_items.setdefault(prj["project"], [])
        prev = items[-1]["rules"] if items else None
        mode, default = mode or "enforce", default or "allow"
        doc = {
            "format": "signafaide-rules/1",
            "project": prj["project"],
            "env": prj["env"],
            "set": set_id,
            "version": len(items) + 1,
            "prev": hash_json(prev) if prev else None,
            "issued": issued or now(),
            "mode": mode,
            "default": default,
            "fail": fail or {},
            "addresses": addresses or {"hosts": [], "cidrs": []},
            "approved": approved,
            "rules": rules,
        }
        if fingerprint_exceptions is not None:
            doc["fingerprint_exceptions"] = fingerprint_exceptions
        if protect is not None:
            doc["protect"] = protect
        item = {"rules": doc, "sig": self.key.sign("rules", hash_json(doc)), "service_key_id": self.key.key_id}
        items.append(item)
        return item

    def _publish_draft(self, api_key, body, how, who):
        """POST /v1/rules (§6, spec 1.1): check ``after`` and the whole document, then sign it."""
        from signafaide import checks as C

        prj = self.projects[api_key]
        items = self.rule_items.setdefault(prj["project"], [])
        newest = items[-1]["rules"]["version"] if items else None
        if body.get("after") != newest:
            return err(400, "bad_request", "Someone published meanwhile: fetch the rule set, merge and try again.")
        d = body.get("draft") or {}
        item = self.publish_rules(
            api_key,
            d.get("rules"),
            mode=d.get("mode"),
            default=d.get("default"),
            fail=d.get("fail"),
            addresses=d.get("addresses"),
            approved=d.get("approved"),
            fingerprint_exceptions=d.get("fingerprint_exceptions"),
            protect=d.get("protect"),
        )
        bad = C.rule_set_errors(item["rules"])
        if bad:
            items.pop()
            return err(400, "bad_request", f"The rule set is not valid: {bad}")
        self.published.append({"project": prj["project"], "version": item["rules"]["version"], "how": how, "who": who})
        return 201, item

    def answer_device(self, status="approved", roles=None):
        """Approve (or refuse) the pending device sign-ins, as a person on the console page does."""
        for d in self.devices.values():
            if d["status"] == "pending":
                d["status"] = status
        self.pending_roles = roles or {}

    def list_update(self, add=(), remove=()):
        """Publish an update of the shared fingerprint list (§11.2)."""
        from signafaide.checks import state_hash

        key = lambda e: (e["kind"], e["fingerprint"])  # noqa: E731
        rm = {key(e) for e in remove}
        self.list_entries = sorted([e for e in self.list_entries if key(e) not in rm] + list(add), key=key)
        prev = hash_json(self.list_updates[-1]["list"]) if self.list_updates else None
        doc = {
            "format": "signafaide-fingerprints/1",
            "list": "shared",
            "type": "update",
            "seq": len(self.list_updates) + 1,
            "prev": prev,
            "issued": now(),
            "add": sorted(add, key=key),
            "remove": sorted(remove, key=key),
            "state_hash": state_hash(self.list_entries),
        }
        self.list_updates.append(
            {"list": doc, "sig": self.key.sign("fingerprints", hash_json(doc)), "service_key_id": self.key.key_id}
        )

    def list_snapshot(self):
        from signafaide.checks import state_hash

        last = hash_json(self.list_updates[-1]["list"]) if self.list_updates else None
        doc = {
            "format": "signafaide-fingerprints/1",
            "list": "shared",
            "type": "snapshot",
            "seq": len(self.list_updates),
            "last": last,
            "issued": now(),
            "entries": self.list_entries,
            "state_hash": state_hash(self.list_entries),
        }
        return {"list": doc, "sig": self.key.sign("fingerprints", hash_json(doc)), "service_key_id": self.key.key_id}

    def rule(self, prj, r, rc):
        """The witness's ruling (§3.5), as the real one decides it (no rate limits here)."""
        from signafaide import checks as C

        env, ch = r["envelope"], r["envelope"]["checks"]
        values = r.get("disclosed") or {}
        items = self.rule_items.get(prj["project"], [])
        doc = items[-1]["rules"] if items else None
        listed = {(e["kind"], e["fingerprint"]) for e in self.list_entries}
        # A match the rule set excepts (§10.1 fingerprint_exceptions) is no match.
        excepted = {(e["kind"], e["fingerprint"]) for e in (doc or {}).get("fingerprint_exceptions") or []}
        hit = any(
            (k, ch["tool"][k]) in listed and (k, ch["tool"][k]) not in excepted
            for k in ("tool", "description", "server")
            if ch["tool"][k]
        )
        missing = []
        if doc is None:
            res = (
                {"result": "block", "basis": "fingerprint", "matched": []}
                if hit
                else {"result": "allow", "basis": "default", "matched": []}
            )
            mode, rules = "enforce", None
        else:
            mode, rules = doc["mode"], {"set": doc["set"], "version": doc["version"], "hash": hash_json(doc)}
            client = next((x for x in ch["rules"] if x["set"] == doc["set"]), None)
            missing = [p for p in C.needed_fields(doc, env["agent"], env["name"]) if p not in ch["disclosed"]]
            if client is not None and client["version"] > doc["version"]:
                res = {"result": "block", "basis": "rules_version", "matched": []}
            elif missing:
                res = {"result": "block", "basis": "fields_missing", "matched": []}
            elif hit:
                res = {"result": "block", "basis": "fingerprint", "matched": []}
            else:
                res = C.evaluate(
                    doc,
                    env["agent"],
                    env["name"],
                    lambda p: values.get(p, C.ABSENT),
                    count=lambda lim: 0,
                    available=lambda p: p in ch["disclosed"],
                )
        g = {
            "v": 1,
            "record_hash": rc["record_hash"],
            "batch_hash": rc["batch_hash"],
            "server_time": rc["batch"]["server_time"],
            "ruling": res["result"] if mode == "enforce" else "allow",
            "mode": mode,
            "basis": res["basis"],
            "matched": res["matched"],
            "missing": missing[:64] if res["basis"] == "fields_missing" else [],
            "rules": rules,
            "fingerprints": len(self.list_updates),
            "reason": f"{res['result'].capitalize()}ed ({res['basis']}).",
        }
        if mode == "watch":
            g["enforce_ruling"] = res["result"]
        # Spec 1.1: what else the evaluation found, each only when not empty.
        if res["basis"] in ("error", "rule", "default"):
            for k in ("would_block", "not_calibrated", "excepted"):
                if res.get(k):
                    g[k] = res[k]
        return g

    def export(self, prj, agent, from_, to):
        """Every agent of the project unless ``agent`` narrows it, as the service does."""
        recs = []
        for r, rc in prj["records"].values():
            env = r["envelope"]
            if (agent and env["agent"] != agent) or (from_ and env["time"] < from_) or (to and env["time"] >= to):
                continue
            recs.append({**r, "receipt": rc})
        recs.sort(key=lambda r: (r["envelope"]["agent"], r["envelope"]["seq"]))
        # Heads of the agents with records in the pack only (§7).
        agents = sorted({r["envelope"]["agent"] for r in recs})
        return self.sign_export(
            {
                "format": "signafaide-pack/1",
                "generated": now(),
                "project": prj["project"],
                "env": prj["env"],
                "service_keys": [self.key_doc],
                "agent_keys": [k for a in agents for k in prj["agents"].get(a, {}).values()],
                "filter": {"agents": [agent] if agent else None, "from": from_, "to": to},
                "heads": [prj["heads"][a] for a in agents if a in prj["heads"]],
                "records": recs,
                "anchors": [],
                # The signed rule set versions (§7): every version this project holds, in version order.
                **({"rule_sets": list(self.rule_items[prj["project"]])} if self.rule_items.get(prj["project"]) else {}),
            }
        )

    def sign_export(self, pack):
        """The export statement (§7): re-sign after the service itself changes a pack."""
        from signafaide.verifier import export_statement

        pack["export_sig"] = ""
        pack["export_sig"] = self.key.sign("export", hash_json(export_statement(pack)))
        return pack

    def _handler(self):
        svc = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _do(self, method):
                u = urllib.parse.urlsplit(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                q = dict(urllib.parse.parse_qsl(u.query))
                svc.client_ids.append(self.headers.get("X-Signafaide-Client"))
                svc.req_headers = dict(self.headers)
                if svc.hang:
                    time.sleep(svc.hang)
                status, obj = svc.route(method, u.path, q, body, self.headers.get("Authorization"))
                data = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
                if status == 304:
                    self.send_response(304)
                    self.end_headers()
                    return
                self.send_response(status)
                self.send_header("Content-Type", "text/plain" if isinstance(obj, str) else "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

            def do_DELETE(self):
                self._do("DELETE")

        return H
