#!/usr/bin/env bash
# Atlas op (RM3254) — point de restauration pré-MEP : `om <svc> sync update --rid <rid>`
# sur le nœud qui porte l'instance. Palier P1 (additif : crée un snapshot, ne détruit rien ;
# la rétention est celle de la ressource opensvc).
# Args validés par le catalogue : <svc> (RE_CONTAINER), <rid> (liste blanche sync#root_*).
#
# Refuse AVANT toute écriture si : om absent, instance locale pas `up`, dataset de la
# ressource introuvable. Un snapshot dont on ne sait pas donner le nom ne sert à rien
# le jour du rollback — on préfère ne pas le prendre et le dire.
# Sortie : UNE ligne JSON {"svc","node","rid","datasets","snapshots":[…]}.
set -euo pipefail
svc="${1:?usage: svc-snapshot.sh <svc> <rid>}"
rid="${2:?usage: svc-snapshot.sh <svc> <rid>}"
node="$(hostname -s)"
command -v om >/dev/null 2>&1 || { echo "opensvc (om) introuvable sur ce nœud." >&2; exit 1; }

avail="$(om "$svc" print status --format json 2>/dev/null \
  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("avail",""))' 2>/dev/null || true)"
if [ "$avail" != "up" ]; then
  echo "instance de '$svc' non active sur $node (avail=${avail:-absent}) — rien exécuté." >&2
  exit 3
fi

datasets="$(om "$svc" get --kw "$rid.dataset" 2>/dev/null | tr ' ' '\n' | sed '/^$/d' || true)"
if [ -z "$datasets" ]; then
  echo "dataset de la ressource $rid introuvable pour '$svc' — rien exécuté." >&2
  exit 4
fi

snaps() { for ds in $datasets; do zfs list -H -t snapshot -o name -d 1 "$ds" 2>/dev/null || true; done | sort; }
before="$(snaps)"
om "$svc" sync update --rid "$rid" >&2
after="$(snaps)"
created="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | sed '/^$/d')"
if [ -z "$created" ]; then
  echo "om a rendu la main mais aucun nouveau snapshot n'apparaît sur : $datasets" >&2
  exit 5
fi

SVC="$svc" NODE="$node" RID="$rid" DS="$datasets" NEW="$created" python3 -c '
import json, os
print(json.dumps({"svc": os.environ["SVC"], "node": os.environ["NODE"], "rid": os.environ["RID"],
                  "datasets": os.environ["DS"].split(), "snapshots": os.environ["NEW"].split()}))
'
