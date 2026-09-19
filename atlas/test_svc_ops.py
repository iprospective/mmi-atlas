#!/usr/bin/env python3
"""test_svc_ops — scripts svc-status.sh / svc-snapshot.sh contre un `om` et un `zfs` simulés (RM3254).

Lancer : python3 test_svc_ops.py   (sortie non nulle si un test échoue)

Les binaires `om`, `zfs`, `hostname` sont des stubs posés en tête de PATH ; l'état du
faux nœud (disponibilité, datasets, snapshots) vit dans un dossier temporaire. On vérifie
surtout ce qui ne doit PAS arriver : aucun `sync update` quand l'instance n'est pas up ou
que le dataset est introuvable.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OPS = HERE / "ops"
FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


OM = r'''#!/usr/bin/env bash
# faux om : $STATE/avail (absent => service inconnu), $STATE/datasets, journal des appels
echo "$*" >> "$STATE/calls"
svc="$1"; shift
[ -f "$STATE/avail" ] || exit 1
case "$1 $2" in
  "print status") printf '{"avail": "%s", "overall": "%s", "frozen": 0}\n' "$(cat $STATE/avail)" "$(cat $STATE/avail)";;
  "get --kw")     [ -f "$STATE/datasets" ] && cat "$STATE/datasets" || exit 1;;
  "sync update")  [ -f "$STATE/nosnap" ] || for ds in $(cat "$STATE/datasets"); do echo "$ds@hourly.snap.2026-09-19.10:00:00" >> "$STATE/snaps"; done;;
  *) exit 2;;
esac
'''
ZFS = r'''#!/usr/bin/env bash
# faux zfs list -H -t snapshot -o name -d 1 <ds>
ds="${@: -1}"
[ -f "$STATE/snaps" ] && grep "^$ds@" "$STATE/snaps" || true
'''


def node(avail=None, datasets=None, snaps=(), nosnap=False):
    st = Path(tempfile.mkdtemp())
    b = st / "bin"; b.mkdir()
    for name, body in (("om", OM), ("zfs", ZFS), ("hostname", "#!/bin/sh\necho node5\n")):
        (b / name).write_text(body); (b / name).chmod(0o755)
    if avail is not None:
        (st / "avail").write_text(avail)
    if datasets is not None:
        (st / "datasets").write_text(datasets)
    if snaps:
        (st / "snaps").write_text("\n".join(snaps) + "\n")
    if nosnap:
        (st / "nosnap").write_text("")
    return st


def run(st, script, *args):
    env = dict(os.environ, STATE=str(st), PATH=f"{st / 'bin'}:{os.environ['PATH']}")
    p = subprocess.run(["bash", str(OPS / script), *args], capture_output=True, text=True, env=env)
    return p


def calls(st):
    f = st / "calls"
    return f.read_text() if f.exists() else ""


print("svc-status")
st = node(avail="up")
p = run(st, "svc-status.sh", "example")
d = json.loads(p.stdout.strip().splitlines()[-1])
check("instance up → avail=up, node=node5", p.returncode == 0 and d["avail"] == "up" and d["node"] == "node5")
st = node(avail="down")
check("instance down → avail=down", json.loads(run(st, "svc-status.sh", "example").stdout)["avail"] == "down")
st = node()  # service inconnu sur ce nœud
p = run(st, "svc-status.sh", "example")
check("service inconnu → avail=absent, code 0 (pas une erreur)",
      p.returncode == 0 and json.loads(p.stdout)["avail"] == "absent")

print("svc-snapshot")
st = node(avail="up", datasets="zfs/lxc/example", snaps=["zfs/lxc/example@hourly.snap.2026-09-19.09:00:00"])
p = run(st, "svc-snapshot.sh", "example", "sync#root_hour")
d = json.loads(p.stdout.strip().splitlines()[-1]) if p.returncode == 0 else {}
check("up + dataset → snapshot créé", p.returncode == 0)
check("seul le NOUVEAU snapshot est rendu (pas celui d'avant)",
      d.get("snapshots") == ["zfs/lxc/example@hourly.snap.2026-09-19.10:00:00"])
check("om appelé avec --rid sync#root_hour", "example sync update --rid sync#root_hour" in calls(st))
check("sortie porte node + datasets", d.get("node") == "node5" and d.get("datasets") == ["zfs/lxc/example"])

st = node(avail="down", datasets="zfs/lxc/example")
p = run(st, "svc-snapshot.sh", "example", "sync#root_hour")
check("instance down → refus code 3", p.returncode == 3)
check("instance down → AUCUN sync update", "sync update" not in calls(st))

st = node(datasets="zfs/lxc/example")  # absent
p = run(st, "svc-snapshot.sh", "example", "sync#root_hour")
check("service absent → refus, aucun sync update", p.returncode == 3 and "sync update" not in calls(st))

st = node(avail="up")  # pas de dataset résolu
p = run(st, "svc-snapshot.sh", "example", "sync#root_hour")
check("dataset introuvable → refus code 4, aucun sync update",
      p.returncode == 4 and "sync update" not in calls(st))

st = node(avail="up", datasets="zfs/lxc/a zfs/lxc/b")
p = run(st, "svc-snapshot.sh", "example", "sync#root_hour")
d = json.loads(p.stdout) if p.returncode == 0 else {}
check("plusieurs datasets → un snapshot par dataset", len(d.get("snapshots", [])) == 2)

st = node(avail="up", datasets="zfs/lxc/example", nosnap=True)
p = run(st, "svc-snapshot.sh", "example", "sync#root_hour")
check("om rend la main sans snapshot visible → code 5 (jamais un succès muet)", p.returncode == 5)

print("ÉCHEC" if FAILED else "TOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
