#!/usr/bin/env python3
"""test_access — substrat partagé : droits (interface ET acteur) + journal (RM2079).

Lancer : python3 test_access.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from access import Rights, AccessLog, result_summary, peer_user, DEFAULT_RIGHTS  # noqa: E402

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


def allowed(r, *a):
    return r.check(*a)[0]


print("— Droits par défaut (par interface) —")
r = Rights()   # table par défaut sûre
check("bot peut op P2 (restart-service)", allowed(r, "atlas-bot", "telegram:1", "op", "restart-service", "P2"))
check("bot peut op P0", allowed(r, "atlas-bot", "telegram:1", "op", "disk-usage", "P0"))
check("www peut op P2", allowed(r, "atlas-www", "www:adm", "op", "restart-service", "P2"))
check("www NE peut PAS aidiag (kind hors liste)", not allowed(r, "atlas-www", "www:adm", "aidiag"))
check("www peut diag", allowed(r, "atlas-www", "www:adm", "diag"))
check("cli peut resolve", allowed(r, "atlas-cli", "cli:root", "resolve"))

print("— Chemin autonome : ingest cloisonné —")
check("ingest peut event", allowed(r, "atlas-ingest", "zabbix", "event"))
check("ingest NE peut PAS op (jamais d'exécution directe)", not allowed(r, "atlas-ingest", "zabbix", "op", "restart-service", "P2"))
check("ingest NE peut PAS diag", not allowed(r, "atlas-ingest", "zabbix", "diag"))

print("— Interface inconnue : lecture seule —")
check("inconnue peut status", allowed(r, "n8n", "x", "status"))
check("inconnue NE peut PAS op", not allowed(r, "n8n", "x", "op", "disk-usage", "P0"))
check("inconnue NE peut PAS event", not allowed(r, "n8n", "x", "event"))

print("— Override PAR ACTEUR (resserre) : plafond abaissé à P1 —")
tbl = json.loads(json.dumps(DEFAULT_RIGHTS))
tbl["actors"]["telegram:junior"] = {"op_max_tier": "P1"}
r2 = Rights(tbl)
check("acteur junior : op P1 (zfs-snapshot) OK", allowed(r2, "atlas-bot", "telegram:junior", "op", "zfs-snapshot", "P1"))
check("acteur junior : op P2 (restart) REFUSÉ (au-dessus du plafond)", not allowed(r2, "atlas-bot", "telegram:junior", "op", "restart-service", "P2"))
check("autre acteur bot : op P2 toujours OK", allowed(r2, "atlas-bot", "telegram:senior", "op", "restart-service", "P2"))

print("— Override PAR ACTEUR : deny_ops / allow_ops —")
tbl2 = json.loads(json.dumps(DEFAULT_RIGHTS))
tbl2["actors"]["www:readonly"] = {"deny_ops": ["restart-service", "restart-lxc"]}
r3 = Rights(tbl2)
check("deny_ops bloque restart-service", not allowed(r3, "atlas-www", "www:readonly", "op", "restart-service", "P2"))
check("deny_ops laisse passer le reste (zfs-snapshot)", allowed(r3, "atlas-www", "www:readonly", "op", "zfs-snapshot", "P1"))
tbl3 = json.loads(json.dumps(DEFAULT_RIGHTS))
tbl3["actors"]["cli:limited"] = {"allow_ops": ["disk-usage"]}
r4 = Rights(tbl3)
check("allow_ops strict : disk-usage OK", allowed(r4, "atlas-cli", "cli:limited", "op", "disk-usage", "P0"))
check("allow_ops strict : hors liste REFUSÉ", not allowed(r4, "atlas-cli", "cli:limited", "op", "service-status", "P0"))

print("— Plafond never bloque toute op —")
check("default (never) refuse P0", not allowed(r, "default-ish", "x", "op", "disk-usage", "P0"))

print("— summary —")
s = r.summary()
check("summary expose la source", s["source"] == "builtin")
check("summary liste les plafonds d'interface", s["interfaces"]["atlas-ingest"] == "never")

print("— peer_user —")
check("uid inconnu → 'uid:N'", peer_user(2_000_111) == "uid:2000111")
check("uid 0 → root", peer_user(0) == "root")

print("— Journal d'accès : écrit, rédigé, append —")
with tempfile.TemporaryDirectory() as d:
    log = AccessLog(Path(d) / "access.jsonl")
    log.record(iface_uid=1001, interface="atlas-bot", actor="telegram:1", kind="op",
               op="restart-service", node=None, args=["password=hunter2", "nginx"],
               allowed=True, result={"ok": True, "exit": 0}, duration_ms=42)
    log.record(iface_uid=1002, interface="atlas-www", actor="www:adm", kind="op",
               op="restart-lxc", args=["calicote"], allowed=False,
               deny_reason="plafond never")
    lines = (Path(d) / "access.jsonl").read_text().strip().splitlines()
    check("2 lignes appendées", len(lines) == 2)
    e0 = json.loads(lines[0])
    check("interface + actor loggés", e0["iface"] == "atlas-bot" and e0["actor"] == "telegram:1")
    check("args RÉDIGÉS (mot de passe caviardé)", "hunter2" not in lines[0] and "CAVIARDÉ" in lines[0])
    check("résultat résumé présent", e0["result"]["ok"] is True and e0["duration_ms"] == 42)
    e1 = json.loads(lines[1])
    check("refus journalisé avec raison", e1["allowed"] is False and "never" in e1["deny_reason"])

print("— result_summary trim —")
rs = result_summary({"ok": True, "exit": 0, "stdout": "x" * 9999, "action": "execute"})
check("ne garde pas stdout volumineux", "stdout" not in rs and rs["ok"] is True and rs["action"] == "execute")
check("error booléanisé", result_summary({"error": "boom"})["error"] is True)

print("\nÉCHEC" if FAILED else "\nTOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
