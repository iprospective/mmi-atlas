#!/usr/bin/env bash
# fleet-deploy-safe.sh — déploie atlas-safe sur N nœuds (RM2050).
#
# Boucle deploy-safe.sh sur une liste de conteneurs (ou toute la flotte). Découvre
# l'hôte de chaque conteneur en direct (lxc-ls sur node3/4/5). Idempotent, tolère les
# échecs (continue + récap final).
#
#   ./fleet-deploy-safe.sh --core-pubkey-file /tmp/core.pub --nodes "tools proxy obs"
#   ./fleet-deploy-safe.sh --core-pubkey-file /tmp/core.pub --all [--exclude "vault secur"]
#   ./fleet-deploy-safe.sh ... --dry-run
set -uo pipefail

HOSTS="node3 node4 node5"
HERE="$(cd "$(dirname "$0")" && pwd)"
PUBFILE="" NODES="" ALL=0 EXCLUDE="" DRY=0

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --core-pubkey-file) PUBFILE="$2"; shift 2 ;;
  --nodes) NODES="$2"; shift 2 ;;
  --all) ALL=1; shift ;;
  --exclude) EXCLUDE="$2"; shift 2 ;;
  --dry-run) DRY=1; shift ;;
  -h|--help) usage 0 ;;
  *) echo "argument inconnu : $1" >&2; usage 1 ;;
esac; done
[[ -n "$PUBFILE" && -r "$PUBFILE" ]] || { echo "--core-pubkey-file requis" >&2; usage 1; }

# Construit la table conteneur→hôte (état live).
declare -A HOST_OF
for h in $HOSTS; do
  for c in $(ssh -o ConnectTimeout=6 "$h" "sudo lxc-ls --running 2>/dev/null" 2>/dev/null); do
    HOST_OF["$c"]="$h"
  done
done

if [[ $ALL -eq 1 ]]; then NODES="${!HOST_OF[*]}"; fi
[[ -n "$NODES" ]] || { echo "aucun nœud (utilise --nodes ou --all)" >&2; exit 1; }

OK=() KO=() SKIP=()
for n in $NODES; do
  [[ " $EXCLUDE " == *" $n "* ]] && { SKIP+=("$n"); continue; }
  host="${HOST_OF[$n]:-}"
  if [[ -z "$host" ]]; then echo "⨯ $n : non trouvé (running) — skip"; KO+=("$n"); continue; fi
  echo "════ $n (sur $host) ════"
  if [[ $DRY -eq 1 ]]; then echo "  [dry-run] deploy-safe.sh --node $n --primary $host"; OK+=("$n"); continue; fi
  if "$HERE/deploy-safe.sh" --node "$n" --primary "$host" --core-pubkey-file "$PUBFILE"; then
    OK+=("$n")
  else
    echo "  ⨯ échec sur $n"; KO+=("$n")
  fi
done

echo; echo "════ RÉCAP ════"
echo "  ✓ OK (${#OK[@]}) : ${OK[*]:-}"
echo "  ⨯ KO (${#KO[@]}) : ${KO[*]:-}"
[[ ${#SKIP[@]} -gt 0 ]] && echo "  – exclus : ${SKIP[*]}"
[[ ${#KO[@]} -eq 0 ]]
