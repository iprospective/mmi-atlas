#!/usr/bin/env python3
"""test_orch_runner — liste blanche du canal orchestrateur → atlas (RM2516, RM3254).

Lancer : python3 test_orch_runner.py   (sortie non nulle si un test échoue)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import orch_runner as orc  # noqa: E402

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


def ok(argv):
    try:
        orc.authorize(argv)
        return True
    except SystemExit:
        return False


check("ops autorisé", ok(["ops"]))
check("run zbx-host autorisé", ok(["run", "zbx-host", "node3.example.net"]))
check("run svc-status --node node5 autorisé", ok(["run", "--node", "node5", "svc-status", "example"]))
check("run --node=node5 svc-snapshot autorisé",
      ok(["run", "--node=node5", "svc-snapshot", "example", "sync#root_hour"]))
check("--dry-run avant l'op toléré", ok(["run", "--dry-run", "zbx-ack", "1", "m"]))
check("la valeur de --node n'est pas prise pour l'op",
      orc.run_op_of(["--node", "node5", "svc-status", "x"]) == "svc-status")
check("restart-lxc refusé (P2, hors canal)", not ok(["run", "--node", "node5", "restart-lxc", "example"]))
check("zfs-snapshot brut refusé (seul svc-snapshot passe)", not ok(["run", "zfs-snapshot", "zfs/lxc/x"]))
check("--node malformé refusé", not ok(["run", "--node", "node5;reboot", "svc-status", "x"]))
check("--node sans valeur refusé", not ok(["run", "--node"]))
check("option inconnue refusée", not ok(["run", "--local", "svc-status", "x"]))
check("sous-commande diag refusée", not ok(["diag", "node5"]))
check("--node node5 SANS op → refusé (node5 n'est pas une op)", not ok(["run", "--node", "node5"]))

print("ÉCHEC" if FAILED else "TOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
