#!/usr/bin/env python3
"""orch_runner — cible forced-command du canal orchestrateur → atlas (RM2516).

Point d'entrée SSH **restreint** : un orchestrateur (PM/audit) présente sa clé dédiée,
autorisée sur atlas avec `command="/usr/bin/python3 /opt/atlas/orch_runner.py",restrict`.
sshd expose la commande demandée dans `SSH_ORIGINAL_COMMAND` ; on la décode **sans
word-splitting shell** (base64 d'un tableau JSON d'arguments), on applique une **liste
blanche**, puis on relaie à `atlas-cli` — le catalogue reste la frontière (validation
op + args + palier + audit).

Format attendu de SSH_ORIGINAL_COMMAND : "atlas <base64(json_list_of_args)>".
Liste blanche : `ops` ; `run zbx-*` ; `run svc-status|svc-snapshot` (RM3254, point de
restauration pré-MEP) ; flags `--dry-run` et `--node <nœud>`. Tout le reste est refusé.
"""
import base64
import json
import os
import re
import sys

ATLAS_CLI = "/opt/atlas/atlas-cli.py"
OP_RE = re.compile(r"^(zbx-[a-z0-9-]+|svc-status|svc-snapshot)$")   # ops Zabbix + pré-MEP
NODE_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
FLAGS = {"--dry-run", "-n"}                      # flags sans valeur admis


def _die(msg, code=2):
    sys.stderr.write(f"canal atlas: {msg}\n")
    sys.exit(code)


def parse(raw):
    parts = (raw or "").split()
    if len(parts) != 2 or parts[0] != "atlas":
        _die("commande invalide (attendu: atlas <payload>)")
    try:
        argv = json.loads(base64.b64decode(parts[1]))
    except Exception:  # noqa: BLE001
        _die("payload illisible")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        _die("argv invalide")
    return argv


def run_op_of(args):
    """Op visée par `run …` : premier argument positionnel, la VALEUR de `--node` sautée.

    Sans ce saut, `run --node node5 svc-status x` désignerait « node5 » comme op. Un flag
    inconnu ou un `--node` malformé est refusé : ce canal n'accepte que ce qu'il connaît."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--node" or a.startswith("--node="):
            val = args[i + 1] if a == "--node" and i + 1 < len(args) else a.partition("=")[2]
            if not NODE_RE.match(val or ""):
                _die(f"--node invalide: {val!r}")
            i += 2 if a == "--node" else 1
            continue
        if a.startswith("-"):
            if a not in FLAGS:
                _die(f"option non autorisée via ce canal: {a!r}")
            i += 1
            continue
        return a
    return ""


def authorize(argv):
    sub = argv[0]
    if sub == "ops":
        return
    if sub == "run":
        op = run_op_of(argv[1:])
        if not OP_RE.match(op):
            _die(f"op non autorisée via ce canal: {op!r} (ops zbx-*, svc-status, svc-snapshot)")
        return
    _die(f"sous-commande non autorisée: {sub!r} (ops|run)")


def main():
    argv = parse(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    authorize(argv)
    # Relais à atlas-cli en mode central (socket du cœur, via le groupe atlas-ifaces).
    os.execv(sys.executable, [sys.executable, ATLAS_CLI, "--json"] + argv)


if __name__ == "__main__":
    main()
