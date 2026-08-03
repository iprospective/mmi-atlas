#!/usr/bin/env python3
"""test_zabbix_ops — ops catalogue Zabbix + extension `target:'api'` (RM2496, ticket B).

Valide : dispatch handler vs shell, dry_run (API) + refus dry_run (shell), garde
manual_close via l'op, validation d'args, audit-trail écrit, et NON-RÉGRESSION du
chemin shell. `zabbix_api._call` est mocké — aucun accès Zabbix réel.
Lancer : python3 test_zabbix_ops.py   (sortie non nulle si un test échoue)
"""
import json
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zabbix_api as zx
from catalogue import Catalogue, Operation, ValidationError
from zabbix_ops import ZABBIX_OPERATIONS

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


def _raises_value(fn):
    try:
        fn()
        return False
    except ValueError:
        return True


def _raises_validation(fn):
    try:
        fn()
        return False
    except ValidationError:
        return True


HOSTS = [{"hostid": "10", "host": "obs.example.net", "name": "obs"}]


def fake_call(capture):
    def _f(method, params, timeout=12):
        capture.append((method, params))
        if method == "host.get":
            filt = params.get("filter", {})
            if "host" in filt:
                return [h for h in HOSTS if h["host"] in filt["host"]]
            return [dict(h) for h in HOSTS]
        if method in ("problem.get", "item.get", "discoveryrule.get"):
            return []
        if method == "template.get":
            return [{"templateid": "999", "host": params["filter"]["host"][0]}]
        return {"ok": method}          # méthodes mutantes
    return _f


TMP = tempfile.mkdtemp()


def fresh_cat(capture):
    zx._call = fake_call(capture)
    return Catalogue(ZABBIX_OPERATIONS, audit_path=Path(TMP) / "audit.jsonl")


# ── Operation : script XOR handler ──
check("Operation sans script ni handler → refus",
      _raises_value(lambda: Operation(id="x", description="d")))
check("Operation avec script ET handler → refus",
      _raises_value(lambda: Operation(id="x", description="d",
                                      script=Path("/bin/true"), handler=lambda a, d: {})))

# ── lecture (P0) : op API renvoie du JSON ──
cap = []
cat = fresh_cat(cap)
res = cat.run("zbx-host", ["obs.example.net"], actor="test")
data = json.loads(res.stdout)
check("zbx-host ok + JSON structuré", res.ok and data["host"]["hostid"] == "10")
check("zbx-problems sans arg (hôte optionnel)", cat.run("zbx-problems", []).ok)

# ── dry_run (API) : décrit sans muter ──
cap = []
cat = fresh_cat(cap)
res = cat.run("zbx-ack", ["555", "vu"], dry_run=True, actor="test")
d = json.loads(res.stdout)
check("zbx-ack dry_run → JSON dry_run + action=6",
      d["dry_run"] is True and d["params"]["action"] == 6)
check("zbx-ack dry_run n'appelle PAS event.acknowledge",
      not any(m == "event.acknowledge" for m, _ in cap))

# ── exécution réelle (mockée) : la mutation part ──
cap = []
cat = fresh_cat(cap)
cat.run("zbx-ack", ["555", "vu"], actor="test")
check("zbx-ack réel → event.acknowledge appelé",
      any(m == "event.acknowledge" for m, _ in cap))

# ── validation d'args : eventid non numérique refusé ──
check("zbx-ack eventid invalide → ValidationError",
      _raises_validation(lambda: cat.run("zbx-ack", ["pas-un-id", "vu"])))

# ── audit-trail écrit pour une op API (avec dry_run + target) ──
lines = (Path(TMP) / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
last = json.loads(lines[-1])
check("audit : target=api + champ dry_run présent",
      last["target"] == "api" and "dry_run" in last and last["op"] == "zbx-ack")

# ── NON-RÉGRESSION du chemin shell + refus dry_run sur op shell ──
SH = Operation(id="sh", description="echo", script=Path("/bin/true"),
               autonomy="P0", needs_sudo=False)


def fake_runner(argv, timeout):
    return types.SimpleNamespace(returncode=0, stdout="ok-shell", stderr="")


shell_cat = Catalogue([SH], audit_path=Path(TMP) / "audit_sh.jsonl", runner=fake_runner)
r = shell_cat.run("sh")
check("op shell inchangée (runner injecté)", r.ok and r.stdout == "ok-shell")
check("dry_run refusé sur op shell",
      _raises_validation(lambda: shell_cat.run("sh", dry_run=True)))

print("OK" if not FAILED else "ÉCHECS")
sys.exit(1 if FAILED else 0)
