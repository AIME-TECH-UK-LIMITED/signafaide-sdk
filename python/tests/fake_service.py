"""An in-process fake of the signafAIde service (SPEC §3, §5, §6) for tests.

It really validates and signs: records are checked (schema, agent key,
signature, chain, content), batched into an RFC 6962 tree and covered by
batch and head signatures from a service key.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from signafaide.crypto import SigningKey, audit_path, b64url, b64url_decode, content_hash, hash_json, key_id, merkle_root, verify_sig
from signafaide.records import now, record_errors, record_hash, registration


def err(status, code, message, **extra):
    return status, {"error": {"code": code, "message": message, "docs": f"https://docs.example/errors#{code}", **extra}}


class FakeService:
    def __init__(self):
        self.key = SigningKey.generate()
        self.key_doc = {"key_id": self.key.key_id, "public_key": b64url(self.key.public_key), "valid_from": "2020-01-01T00:00:00.000Z", "valid_to": None}
        self.projects = {}  # api_key -> project
        self.calls = []
        self.fail = None  # (status, code, message) returned once for the next /v1/records
        self.lock = threading.Lock()
        self.sandbox_n = 0
        self.registrations = []
        self.client_ids = []  # X-Signafaide-Client of every request
        self.events = []
        handler = self._handler()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def add_project(self, api_key, env="test"):
        self.n_projects = getattr(self, "n_projects", 0) + 1
        prj = {"project": f"prj_01JC{self.n_projects:022d}", "env": env, "agents": {}, "heads": {}, "records": {}, "batches": [], "used": 0}
        self.projects[api_key] = prj
        return prj

    # --- routing --------------------------------------------------------------

    def route(self, method, path, query, body, auth):
        self.calls.append((method, path))
        if method == "GET" and path == "/healthz":
            return 200, "ok"
        if method == "GET" and path == "/.well-known/signafaide-keys.json":
            return 200, {"keys": [self.key_doc]}
        if method == "POST" and path == "/v1/sandbox":
            self.sandbox_n += 1
            key = "sfa_test_" + f"{self.sandbox_n:032d}"
            prj = self.add_project(key)
            return 200, {"project": prj["project"], "api_key": key, "claim_url": f"{self.url}/app/claim/{self.sandbox_n}", "free_quota": 1000,
                         "terms_url": f"{self.url}/legal/terms", "privacy_url": f"{self.url}/legal/privacy"}
        if method == "POST" and path == "/v1/events":
            self.events.append(body.get("name"))
            return 200, {}
        prj = self.projects.get((auth or "").removeprefix("Bearer "))
        if prj is None:
            return err(401, "invalid_key", "The API key is not valid; run `signafaide init` for a new sandbox key.")
        if method == "GET" and path == "/v1/project":
            return 200, {"project": prj["project"], "env": prj["env"]}
        if method == "POST" and path == "/v1/agents":
            pk = body["public_key"]
            kid = key_id(b64url_decode(pk))
            if any(kid in keys for name, keys in prj["agents"].items() if name != body["name"]):
                return err(400, "invalid_record", "This key is registered to another agent; generate a new key for this agent.")
            h = hash_json(registration(prj["project"], prj["env"], body["name"], pk, body.get("valid_from") or ""))
            if not verify_sig(pk, "register", h, body.get("proof") or ""):
                return err(400, "bad_signature", "proof must be the new key's signature over the registration (domain register).")
            ag = prj["agents"].setdefault(body["name"], {})
            active = {k: v for k, v in ag.items() if v["valid_to"] is None and k != kid}
            if active and kid not in ag:
                rot = body.get("rotation") or {}
                if rot.get("key_id") not in active or not verify_sig(active[rot["key_id"]]["public_key"], "rotate", h, rot.get("sig") or ""):
                    return err(400, "bad_signature", "This agent already has an active key: sign the registration with it (rotation), or revoke it in the console first.")
                # A rotation retires the key that signed it (§2.4), after its newest record.
                newest = max((r["envelope"]["time"] for r, _ in prj["records"].values() if r["key_id"] == rot["key_id"]), default=None)
                t = now()
                if newest and newest >= t:
                    from signafaide.verifier import _epoch_ms, _fmt
                    t = _fmt(_epoch_ms(newest) + 1)
                active[rot["key_id"]]["valid_to"] = t
            self.registrations.append(body)
            ag.setdefault(kid, {"agent": body["name"], "key_id": kid, "public_key": pk, "valid_from": body["valid_from"], "valid_to": None})
            retired = [{"key_id": k, "valid_to": v["valid_to"]} for k, v in sorted(ag.items()) if v["valid_to"] is not None]
            return 200, {"agent": body["name"], "key_id": kid, "retired": retired}
        if method == "POST" and path == "/v1/records":
            if self.fail:
                f, self.fail = self.fail, None
                return f
            with self.lock:
                return self.submit(prj, body.get("records") or [])
        if method == "GET" and path.startswith("/v1/heads/"):
            agent = path.rsplit("/", 1)[1]
            return 200, prj["heads"].get(agent) or {}
        if method == "GET" and path == "/v1/usage":
            return 200, {"period": "2026-11", "used": prj["used"], "quota": 1000}
        if method == "GET" and path == "/v1/export":
            return 200, self.export(prj, query.get("agent"), query.get("from"), query.get("to"))
        if method == "POST" and path == "/v1/experiments":
            self.experiments = getattr(self, "experiments", []) + [body]
            return 201, {"id": f"exp_{len(self.experiments)}", "n": len(body["rows"]), "url": f"{self.url}/app/experiments/{len(self.experiments)}"}
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
                return err(400, "invalid_record", "envelope.project and envelope.env must be this key's project and env.")
            # As the real service: an unknown agent is unknown_agent; a known agent's unregistered key is bad_signature.
            keys = prj["agents"].get(env["agent"])
            if keys is None:
                return err(400, "unknown_agent", f"agent '{env['agent']}' is not registered in this project and env; call POST /v1/agents first.")
            key = keys.get(r["key_id"])
            if key is None:
                return err(400, "bad_signature", f"key {r['key_id']} is not registered for agent '{env['agent']}'; register it with POST /v1/agents.")
            if key["valid_to"] is not None:
                return err(400, "bad_signature", f"key {r['key_id']} was retired or revoked at {key['valid_to']}; it cannot add records.")
            if not verify_sig(key["public_key"], "record", h, r["sig"]):
                return err(400, "bad_signature", "The record signature does not verify; sign record_hash with domain 'record'.")
            if ("content" in r) != ("salt" in r) or ("content" in r and content_hash(r["content"], r["salt"]) != env["content_hash"]):
                return err(400, "content_mismatch", "content does not match content_hash; send the exact content you hashed.")
            seq, last = tips.get(env["agent"], (0, None))
            if env["seq"] != seq + 1 or env["prev"] != last:
                return err(409, "chain_conflict", "This record does not extend the service chain; the head is attached.", head={"agent": env["agent"], "seq": seq, "record_hash": last})
            tips[env["agent"]] = (env["seq"], h)
            new.append(r)
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
                head = {"project": prj["project"], "env": prj["env"], "agent": agent, "seq": seq, "record_hash": last, "server_time": batch["server_time"]}
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
                prj["records"][hashes[i]] = (r, rc)
                prj["used"] += 1
        for r in records:
            receipts.append(prj["records"][record_hash(r)][1])
        return 200, {"receipts": receipts, "heads": heads}

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
        return self.sign_export({
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
        })

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
                status, obj = svc.route(method, u.path, q, body, self.headers.get("Authorization"))
                data = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/plain" if isinstance(obj, str) else "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

        return H
