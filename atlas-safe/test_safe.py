#!/usr/bin/env python3
"""test_safe — auto-tests du catalogue read-only atlas-safe (RM2050).

Lancer : PYTHONPATH=../atlas ATLAS_OPS_DIR=$PWD/ops python3 test_safe.py
(ou via run-tests.sh). Vérifie : ops chargées, validation des args (anti-injection),
read-only effectif (disk-usage tourne), et sudoers généré = 1 ligne par op privilégiée.
"""
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "atlas"))   # catalogue.py partagé
os.environ.setdefault("ATLAS_OPS_DIR", str(HERE / "ops"))

from catalogue import Catalogue, ValidationError   # noqa: E402
from operations_safe import OPERATIONS, LOG_NAMES   # noqa: E402

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


def expect_reject(name, fn):
    try:
        fn()
        check(name, False)
    except ValidationError:
        check(name, True)


print("— Registre atlas-safe —")
ops = {o.id: o for o in OPERATIONS}
check("5 ops vettées", len(OPERATIONS) == 5)
check("toutes read-only (P0)", all(o.autonomy == "P0" for o in OPERATIONS))
check("disk-usage & service-status sans sudo",
      not ops["disk-usage"].needs_sudo and not ops["service-status"].needs_sudo)
check("journal/tail-log/db-instances privilégiés",
      ops["journal"].needs_sudo and ops["tail-log"].needs_sudo and ops["db-instances"].needs_sudo)

print("— Validation des args (anti-injection / anti-chemin libre) —")
audit = Path(tempfile.mkdtemp()) / "a.jsonl"
cat = Catalogue(OPERATIONS, audit_path=audit)
expect_reject("op inconnue rejetée", lambda: cat.run("rm-rf"))
expect_reject("tail-log : log hors liste blanche rejeté",
              lambda: ops["tail-log"].validate_args(["/etc/shadow"]))
expect_reject("tail-log : pattern avec métacaractères rejeté",
              lambda: ops["tail-log"].validate_args(["syslog", "50", "$(id)"]))
expect_reject("tail-log : lines hors borne rejeté",
              lambda: ops["tail-log"].validate_args(["syslog", "99999"]))
check("tail-log : log+lines+pattern valides acceptés",
      ops["tail-log"].validate_args(["syslog", "50", "error"]) == ["syslog", "50", "error"])
expect_reject("journal : unité invalide rejetée",
              lambda: ops["journal"].validate_args(["a;b"]))
expect_reject("service-status : injection rejetée",
              lambda: ops["service-status"].validate_args(["; reboot"]))
check("journal : unité valide acceptée",
      ops["journal"].validate_args(["mariadb", "100"]) == ["mariadb", "100"])
check("liste blanche logs alignée", set(LOG_NAMES) == {"syslog", "auth", "kern", "daemon", "dpkg"})

print("— Read-only effectif —")
res = cat.run("disk-usage", actor="test")
check("disk-usage s'exécute (read-only)", res.ok and res.exit_code == 0)

print("— Sudoers généré (1 ligne NOPASSWD par op privilégiée) —")
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "gen_sudoers", HERE.parent / "atlas" / "gen-sudoers.py")
gs = importlib.util.module_from_spec(_spec)
os.environ["ATLAS_OPS_MODULE"] = "operations_safe"
os.environ["ATLAS_USER"] = "atlas-safe"
os.environ["ATLAS_PROD_OPS_DIR"] = "/opt/atlas-safe/ops"
_spec.loader.exec_module(gs)
sudoers = gs.render()
n_priv = sum(1 for o in OPERATIONS if o.needs_sudo)
check("une ligne NOPASSWD par op privilégiée",
      sum(1 for ln in sudoers.splitlines() if "NOPASSWD" in ln) == n_priv)
check("sudoers : user atlas-safe + chemin /opt/atlas-safe/ops",
      "atlas-safe ALL=(root) NOPASSWD: /opt/atlas-safe/ops/journal.sh" in sudoers)
check("sudoers : aucune op read-only-pure (disk-usage absent)", "disk-usage.sh" not in sudoers)

print("ÉCHEC" if FAILED else "TOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
