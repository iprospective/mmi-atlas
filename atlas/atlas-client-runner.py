#!/usr/bin/env python3
"""atlas-client-runner — point d'entrée SSH `command=` forcé d'atlas-client (RM2042).

Bout RÉCEPTEUR du dispatch d'ACTION du cœur (frontière 2 de l'architecture). Le cœur se
connecte par `ssh atlas-client@<nœud> "<op_id> [args]"` ; sa clé est **command=-forcée**
vers ce script. La requête réelle arrive dans `SSH_ORIGINAL_COMMAND` ; on la valide via le
catalogue ACTING (operations.py), on exécute (sudo -n sur l'op vettée, sudoers ciblé), on
renvoie du **JSON**. Aucune commande hors catalogue n'est possible — même avec un shell,
l'appelant ne peut déclencher qu'une op vettée de CE nœud.

Pendant du runner read-only `atlas-safe-runner.py` (RM2050), côté ACTION. Le dispatch
d'action distant côté cœur reste à câbler (RM1813 reste) ; ce nœud est néanmoins prêt.

Sans argument → liste les ops (health-check du cœur).
"""
import json
import os
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalogue import Catalogue, ValidationError  # noqa: E402
from operations import OPERATIONS                  # noqa: E402  (catalogue ACTING)

AUDIT = os.environ.get("ATLAS_CLIENT_AUDIT",
                       str(Path(__file__).resolve().parent / "data" / "audit.jsonl"))
CAT = Catalogue(OPERATIONS, audit_path=AUDIT)


def out(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")


def main():
    raw = os.environ.get("SSH_ORIGINAL_COMMAND", "").strip()
    try:
        parts = shlex.split(raw)
    except ValueError as e:
        return out({"ok": False, "error": f"commande illisible : {e}"})
    if not parts:
        return out({"ok": True, "node": os.uname().nodename,
                    "ops": [o.id for o in CAT.list()]})
    op_id, args = parts[0], parts[1:]
    try:
        res = CAT.run(op_id, args, actor="core-via-ssh")
        out({"ok": res.ok, "op": op_id, "args": args, "exit": res.exit_code,
             "stdout": res.stdout, "stderr": res.stderr, "duration_ms": res.duration_ms,
             "node": os.uname().nodename})
    except ValidationError as e:
        out({"ok": False, "op": op_id, "args": args, "error": str(e)})


if __name__ == "__main__":
    main()
