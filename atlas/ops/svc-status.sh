#!/usr/bin/env bash
# Atlas op (RM3254) — état de l'instance LOCALE d'un service opensvc. Palier P0 (lecture).
# Arg <svc> déjà validé par le catalogue (RE_CONTAINER). Sortie : UNE ligne JSON
#   {"svc", "node", "avail": up|down|warn|n/a|absent, "overall", "frozen"}
# « absent » = service inconnu sur ce nœud (pas une erreur : l'orchestrateur interroge
# chaque nœud candidat pour trouver celui qui porte l'instance up).
set -euo pipefail
svc="${1:?usage: svc-status.sh <svc>}"
node="$(hostname -s)"
if ! command -v om >/dev/null 2>&1; then
  echo "opensvc (om) introuvable sur ce nœud." >&2
  exit 1
fi
if ! raw="$(om "$svc" print status --format json 2>/dev/null)"; then
  printf '{"svc":"%s","node":"%s","avail":"absent"}\n' "$svc" "$node"
  exit 0
fi
SVC="$svc" NODE="$node" python3 -c '
import json, os, sys
try:
    d = json.loads(sys.stdin.read() or "{}")
except ValueError:
    d = {}
print(json.dumps({"svc": os.environ["SVC"], "node": os.environ["NODE"],
                  "avail": d.get("avail", "n/a"), "overall": d.get("overall", "n/a"),
                  "frozen": bool(d.get("frozen"))}))
' <<<"$raw"
