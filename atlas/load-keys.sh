#!/usr/bin/env bash
# load-keys.sh — charge les clés d'orchestration Atlas dans l'agent (RM2058).
#
# À lancer (INTERACTIF) après un redémarrage du conteneur atlas : ssh-add demande
# la passphrase de chaque clé, qui restent alors EN MÉMOIRE dans l'agent (hors
# snapshot). Tant que ce n'est pas fait, le diagnostic DISTANT (on-target) est en
# pause ; le reste d'Atlas (alertes, décision, bot, ops locales) fonctionne.
#
#   # sur le conteneur atlas, en tant que `atlas` :
#   sudo runuser -u atlas -- /opt/atlas/load-keys.sh
#
# Idempotent (ré-ajouter une clé déjà présente est sans effet).
set -uo pipefail
export SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-/run/atlas-ssh-agent/agent.sock}"

if ! ssh-add -l >/dev/null 2>&1 && [ ! -S "$SSH_AUTH_SOCK" ]; then
  echo "⚠ agent introuvable ($SSH_AUTH_SOCK) — atlas-ssh-agent.service tourne-t-il ?" >&2
  exit 1
fi

n=0
while IFS= read -r k; do
  echo "→ ssh-add $k"
  ssh-add "$k" && n=$((n+1))
done < <(find /opt/atlas/.ssh -maxdepth 1 -type f -name 'atlas-*' ! -name '*.pub' | sort)

echo "✓ $n clé(s) chargée(s). État de l'agent :"
ssh-add -l
