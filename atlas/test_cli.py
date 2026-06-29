#!/usr/bin/env python3
"""test_cli — atlas-cli : mode dual (central/local) + listing + runner local (RM2041).

Lancer : python3 test_cli.py
Exécute le vrai CLI en sous-processus : `ops` (pur), runner LOCAL réel sur une op
read-only (disk-usage), et résolution de mode sans cœur joignable.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLI = HERE / "atlas-cli.py"
FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


def run(*argv, sock="/nonexistent/atlas.sock", audit=None):
    env = dict(os.environ)
    env["ATLAS_SOCKET"] = sock
    if audit:
        env["ATLAS_AUDIT_PATH"] = audit
    return subprocess.run([sys.executable, str(CLI), *argv], cwd=str(HERE),
                          env=env, capture_output=True, text=True)


print("— ops (pur, sans cœur) —")
r = run("ops")
check("ops liste le catalogue", r.returncode == 0 and "restart-service" in r.stdout)
check("ops montre les paliers", "[P0]" in r.stdout and "[P2]" in r.stdout)
rj = run("--json", "ops")
data = json.loads(rj.stdout)
check("ops --json : liste structurée", isinstance(data, list) and any(o["id"] == "disk-usage" for o in data))

print("— runner LOCAL réel (op read-only disk-usage) —")
with tempfile.TemporaryDirectory() as d:
    audit = str(Path(d) / "audit.jsonl")
    r = run("--local", "run", "disk-usage", audit=audit)
    check("run local disk-usage → exit 0", r.returncode == 0)
    check("sortie df présente", "Filesystem" in r.stdout or "Sys." in r.stdout or "%" in r.stdout)
    check("audit JSONL écrit", Path(audit).exists() and "disk-usage" in Path(audit).read_text())

print("— runner local : op inconnue refusée —")
r = run("--local", "run", "rm-rf-tout")
check("op inconnue → exit 2 + message", r.returncode == 2 and "inconnue" in (r.stdout + r.stderr).lower())

print("— runner local : --node interdit —")
r = run("--local", "run", "disk-usage", "--node", "node5")
check("--node en local → exit 2", r.returncode == 2 and "local" in (r.stdout + r.stderr).lower())

print("— résolution de mode sans cœur —")
r = run("status")            # auto → pas de socket → local → status est central → refus
check("status auto sans cœur → exit 2 (central requis)", r.returncode == 2)
r = run("--central", "status")
check("--central forcé sans socket → exit 3", r.returncode == 3)
r = run("diag", "mmi")       # auto → local → diag est central → refus
check("diag auto sans cœur → exit 2", r.returncode == 2)

print("— flags exclusifs —")
r = run("--local", "--central", "ops")
# ops court-circuite avant resolve_mode, donc --local/--central seuls sur 'ops' n'entrent
# pas en conflit ; on teste l'exclusivité sur une commande qui résout le mode.
r = run("--local", "--central", "status")
check("--local + --central → exit 2", r.returncode == 2 and "exclusif" in (r.stdout + r.stderr))

print("\nÉCHEC" if FAILED else "\nTOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
