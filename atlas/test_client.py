#!/usr/bin/env python3
"""test_client — atlas-client-runner : commande forcée SSH vettée (RM2042).

Lancer : python3 test_client.py
Exécute le runner en sous-processus avec SSH_ORIGINAL_COMMAND (comme SSH le ferait).
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "atlas-client-runner.py"
FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


def run(cmd, audit):
    env = dict(os.environ)
    env["SSH_ORIGINAL_COMMAND"] = cmd
    env["ATLAS_CLIENT_AUDIT"] = audit
    r = subprocess.run([sys.executable, str(RUNNER)], cwd=str(HERE),
                       env=env, capture_output=True, text=True)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"_raw": r.stdout, "_err": r.stderr}


with tempfile.TemporaryDirectory() as d:
    audit = str(Path(d) / "audit.jsonl")

    print("— commande vide → liste des ops (health-check) —")
    o = run("", audit)
    check("ops listées", o.get("ok") and "restart-service" in (o.get("ops") or []))
    check("node renseigné", bool(o.get("node")))

    print("— op read-only vettée (disk-usage) → exécutée —")
    o = run("disk-usage", audit)
    check("disk-usage ok", o.get("ok") is True and o.get("op") == "disk-usage")

    print("— hors catalogue → refusé (aucune exécution arbitraire) —")
    o = run("rm -rf /", audit)
    check("commande arbitraire refusée", o.get("ok") is False and "inconnue" in (o.get("error") or "").lower())

    print("— op vettée mais argument invalide → refusé AVANT exécution —")
    o = run("restart-service", audit)   # arg 'service' manquant → ValidationError (pas de sudo lancé)
    check("arg manquant refusé", o.get("ok") is False and "manquant" in (o.get("error") or "").lower())
    o = run("service-status 'nginx; rm -rf /'", audit)   # motif RE_SERVICE → rejet
    check("argument à métacaractères rejeté", o.get("ok") is False and "invalide" in (o.get("error") or "").lower())

    print("— audit écrit pour ce qui s'exécute —")
    check("audit JSONL contient disk-usage", Path(audit).exists() and "disk-usage" in Path(audit).read_text())

print("\nÉCHEC" if FAILED else "\nTOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
