#!/usr/bin/env python3
"""test_dispatch — résolution + dispatch d'action atlas-client (RM2092).

Lancer : python3 test_dispatch.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import safe_dispatch as sd          # noqa: E402
import client_dispatch as cd        # noqa: E402

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


# Registre orienté read-only (defaults = atlas-safe) + un nœud avec proxyjump/clé.
REG = {"defaults": {"user": "atlas-safe", "key": "/k/safe", "domain": "lan"},
       "nodes": {"cli": {"endpoint": "1.2.3.4", "proxyjump": "gw", "key": "/k/cli"}}}

print("— safe_dispatch.resolve inchangé (rétro-compat) —")
r = sd.resolve("node3", registry=REG)
check("safe : user/key/host par défaut", r["user"] == "atlas-safe" and r["key"] == "/k/safe" and r["host"] == "node3.lan")
r = sd.resolve("cli", registry=REG)
check("safe : override nœud (endpoint/proxyjump/key)", r["host"] == "1.2.3.4" and r["proxyjump"] == "gw" and r["key"] == "/k/cli")

print("— client_dispatch.resolve : force le compte/clé atlas-client —")
r = cd.resolve("node3", registry=REG)
check("client : user forcé atlas-client (ignore defaults safe)", r["user"] == "atlas-client")
check("client : clé forcée atlas-client", r["key"] == cd.CLIENT_KEY)
check("client : reachabilité conservée (host)", r["host"] == "node3.lan")
r = cd.resolve("cli", registry=REG)
check("client : proxyjump conservé, user/clé forcés",
      r["host"] == "1.2.3.4" and r["proxyjump"] == "gw" and r["user"] == "atlas-client" and r["key"] == cd.CLIENT_KEY)

print("— run_op appelle ssh_json avec la bonne cible (ssh_json mocké) —")
calls = {}
_orig = sd.ssh_json
def _fake(rr, op, args=(), *, timeout=30):
    calls.update(r=rr, op=op, args=list(args), timeout=timeout)
    return {"ok": True, "op": op, "exit": 0, "stdout": "done", "duration_ms": 12}
sd.ssh_json = _fake
try:
    out = cd.run_op("node3", "restart-service", ["nginx"], timeout=45)
    check("run_op ok + op/args transmis", out["ok"] and calls["op"] == "restart-service" and calls["args"] == ["nginx"])
    check("run_op vise bien atlas-client", calls["r"]["user"] == "atlas-client" and calls["r"]["host"] == "node3.lan")
    check("run_op propage le timeout", calls["timeout"] == 45)
finally:
    sd.ssh_json = _orig

print("— ssh_json : cible définie même sur échec (bug 'target' corrigé) —")
import inspect
src = inspect.getsource(sd.ssh_json)
check("target défini avant usage", "target = r.get(" in src and src.index("target = r.get(") < src.index("timeout SSH {target}"))

print("\nÉCHEC" if FAILED else "\nTOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
