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

print("— Registre v1 privilégié (RM1817) —")
ops = {o.id: o for o in OPERATIONS}
check("restart-service privilégié (needs_sudo)", ops["restart-service"].needs_sudo)
check("zfs-snapshot palier P1", ops["zfs-snapshot"].autonomy == "P1")
expect_reject("restart-service rejette une injection",
              lambda: ops["restart-service"].validate_args(["a;b"]))
check("zfs-snapshot accepte dataset + label",
      ops["zfs-snapshot"].validate_args(["zfs/lxc/sandbox", "pre"]) == ["zfs/lxc/sandbox", "pre"])
check("zfs-snapshot label optionnel",
      ops["zfs-snapshot"].validate_args(["zfs/lxc/sandbox"]) == ["zfs/lxc/sandbox"])
expect_reject("zfs-snapshot rejette '@' dans le dataset",
              lambda: ops["zfs-snapshot"].validate_args(["zfs/lxc/sandbox@x"]))
expect_reject("restart-lxc rejette un nom invalide",
              lambda: ops["restart-lxc"].validate_args(["../etc"]))
check("tail-log accepte un log listé + nb lignes",
      ops["tail-log"].validate_args(["syslog", "100"]) == ["syslog", "100"])
expect_reject("tail-log rejette un log hors liste blanche",
              lambda: ops["tail-log"].validate_args(["/etc/shadow"]))
expect_reject("tail-log rejette lines hors borne",
              lambda: ops["tail-log"].validate_args(["syslog", "9999"]))

print("— Génération du sudoers —")
import importlib.util
_spec = importlib.util.spec_from_file_location(
    "gen_sudoers", Path(__file__).resolve().parent / "gen-sudoers.py")
gs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gs)
sudoers = gs.render()
n_priv = sum(1 for o in OPERATIONS if o.needs_sudo)
check("sudoers : une ligne NOPASSWD par op privilégiée",
      sum(1 for ln in sudoers.splitlines() if "NOPASSWD" in ln) == n_priv)
check("sudoers : aucune op read-only (disk-usage absent)", "disk-usage.sh" not in sudoers)
check("sudoers : chemin prod /opt/atlas/ops",
      "/opt/atlas/ops/restart-service.sh" in sudoers)

# ── RM3254 : ops opensvc de point de restauration pré-MEP ───────────────────
check("svc-status palier P0", ops["svc-status"].autonomy == "P0")
check("svc-snapshot palier P1", ops["svc-snapshot"].autonomy == "P1")
check("svc-snapshot accepte svc + rid de la liste blanche",
      ops["svc-snapshot"].validate_args(["example", "sync#root_hour"]) == ["example", "sync#root_hour"])
expect_reject("svc-snapshot rejette un rid hors liste (sync#all)",
              lambda: ops["svc-snapshot"].validate_args(["example", "sync#all"]))
expect_reject("svc-snapshot exige le rid", lambda: ops["svc-snapshot"].validate_args(["example"]))
expect_reject("svc-status rejette un nom de service avec espace/;",
              lambda: ops["svc-status"].validate_args(["example;reboot"]))
check("sudoers : svc-snapshot.sh présent", "/opt/atlas/ops/svc-snapshot.sh" in sudoers)

print("ÉCHEC" if FAILED else "TOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
