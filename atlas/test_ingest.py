#!/usr/bin/env python3
"""test_ingest — auto-tests de l'ingestion + chemin événement du cœur (RM1813).

Lancer : python3 test_ingest.py

Tout est in-process et hermétique : un **faux runner** est injecté dans le
catalogue du cœur → aucune commande réelle (ni sudo) n'est lancée.
"""
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


def load(name, filename, env=None):
    if env:
        os.environ.update(env)
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── atlas-ingest : signature + normalisation (unitaire) ─────────────────────
print("— atlas-ingest : HMAC + normalisation —")
ingest = load("atlas_ingest", "atlas-ingest.py", {"ATLAS_INGEST_SECRET": "s3cr3t"})

body = b'{"host":"web1","trigger":"FPM down","severity":"High","state":"problem"}'
good = "sha256=" + hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
check("signature valide acceptée", ingest.verify_sig(body, good))
check("signature falsifiée rejetée", not ingest.verify_sig(body, "sha256=deadbeef"))
check("signature absente rejetée", not ingest.verify_sig(body, ""))
check("corps altéré → signature invalide", not ingest.verify_sig(body + b"x", good))

norm = ingest.normalize(json.loads(body))
check("normalize : severity en minuscules", norm["severity"] == "high")
check("normalize : state en majuscules", norm["state"] == "PROBLEM")
check("normalize : source=zabbix", norm["source"] == "zabbix")
check("normalize : champs alternatifs (hostname/trigger_name)",
      ingest.normalize({"hostname": "h", "trigger_name": "t"})["host"] == "h")

# ── cœur : chemin événement + résolution (in-process, faux runner) ──────────
print("— cœur : chemin événement (decide → execute/approve/notify) —")
tmp = Path(tempfile.mkdtemp())
core = load("atlas_core", "atlas-core.py", {
    "ATLAS_DATA_DIR": str(tmp),
    "ATLAS_DECISION_STATE": str(tmp / "state.json"),
    "ATLAS_DECISIONS_LOG": str(tmp / "decisions.jsonl"),
})


class FakeProc:
    returncode = 0
    stdout = "FAKE-OK"
    stderr = ""


core.CAT._runner = lambda argv, timeout: FakeProc()  # aucune commande réelle
UID = os.getuid()


def event(trigger, host="web1", sev="high", state="PROBLEM", item="calicote-74"):
    return {"event": {"host": host, "trigger": trigger, "severity": sev,
                      "state": state, "item": item}}


r = core.handle_event(event("disk space 95% used", sev="average"), UID)
check("P0 (disk) → notify", r["action"] == "notify" and r["tier"] == "P0")

r = core.handle_event(event("PHP FPM pool down"), UID)
check("P1 (FPM down) → execute", r["action"] == "execute" and r["tier"] == "P1")
check("P1 : op restart-service exécutée (faux runner)",
      r.get("result", {}).get("ok") and r["result"]["stdout"] == "FAKE-OK")

r = core.handle_event(event("LXC container unreachable", host="mmi"), UID)
check("P2 (container down) → approve + token", r["action"] == "approve" and r.get("token"))
token = r["token"]

r = core.handle_event(event("host reboot required"), UID)
check("never (reboot) → notify", r["action"] == "notify" and r["tier"] == "never")

print("— cœur : résolution d'approbation P2 —")
r = core.handle_resolve({"token": token, "approved": False}, UID)
check("resolve refusé → denied (aucune exécution)", r["action"] == "denied")
r = core.handle_resolve({"token": token, "approved": True}, UID)
check("token déjà consommé → erreur", not r["ok"])

r2 = core.handle_event(event("LXC container down", host="srv-x"), UID)
r = core.handle_resolve({"token": r2["token"], "approved": True}, UID)
check("resolve approuvé → executed (op lancée)",
      r["action"] == "executed" and r["result"]["stdout"] == "FAKE-OK")
check("token inconnu → erreur", not core.handle_resolve({"token": "x", "approved": True}, UID)["ok"])

print("— cœur : persistance & journaux —")
check("état du moteur persisté", (tmp / "state.json").exists())
check("journal de décisions écrit",
      (tmp / "decisions.jsonl").exists() and (tmp / "decisions.jsonl").read_text().strip())

print("— cœur : rétro-compat op directe (RM2039) —")
r = core.handle_op({"op": "disk-usage", "args": [], "actor": "test"}, UID)
check("op directe disk-usage toujours OK", r.get("ok") and r["stdout"] == "FAKE-OK")
check("type de message inconnu rejeté",
      core.HANDLERS.get("bogus") is None)

print("ÉCHEC" if FAILED else "TOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
