#!/usr/bin/env python3
"""test_catalogue — auto-tests du framework catalogue (RM1816).

Lancer : python3 test_catalogue.py   (sortie non nulle si un test échoue)
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalogue import ArgSpec, Catalogue, ValidationError, RE_SERVICE
from operations import OPERATIONS

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


print("— Validation des arguments —")
choice = ArgSpec("mode", "choice", choices=("start", "stop"))
check("choice accepte une valeur listée", choice.validate("start") == "start")
expect_reject("choice rejette une valeur hors-liste", lambda: choice.validate("rm"))

tok = ArgSpec("service", "token", pattern=RE_SERVICE)
check("token accepte un nom valide", tok.validate("php8.1-fpm.service") == "php8.1-fpm.service")
for bad in ("; rm -rf /", "a b", "$(id)", "a;b", "`x`", "a|b", "../x"):
    expect_reject(f"token rejette l'injection {bad!r}", lambda b=bad: tok.validate(b))

intspec = ArgSpec("n", "int", min=1, max=5)
check("int accepte dans les bornes", intspec.validate("3") == "3")
expect_reject("int rejette hors borne", lambda: intspec.validate("9"))
expect_reject("int rejette non-entier", lambda: intspec.validate("x"))

print("— Catalogue —")
audit = Path(tempfile.mkdtemp()) / "audit.jsonl"
cat = Catalogue(OPERATIONS, audit_path=audit)
expect_reject("opération inconnue rejetée", lambda: cat.run("nope"))
expect_reject("argument en trop rejeté", lambda: cat.run("disk-usage", ["x"]))
expect_reject("injection d'arg rejetée AVANT exécution",
              lambda: cat.run("service-status", ["; reboot"]))

res = cat.run("disk-usage", actor="test")
check("disk-usage s'exécute (read-only)", res.ok and res.exit_code == 0)
check("audit JSONL écrit", audit.exists() and audit.read_text(encoding="utf-8").strip() != "")

print("ÉCHEC" if FAILED else "TOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
