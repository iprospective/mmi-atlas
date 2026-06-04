#!/usr/bin/env bash
# deploy-atlas.sh — déploie les opérations du catalogue + le sudoers sur UN nœud
# ssh-joignable (RM1817). À lancer depuis le repo (orchestration), l'utilisateur
# distant devant être root (ou sudo). Le user `atlas` doit déjà exister sur le
# nœud (provision-atlas.sh, RM1815).
#
#   ./deploy-atlas.sh <ssh-node>
#
# Étapes : génère le sudoers depuis le registre → valide localement (visudo -c) →
# pousse ops/ dans /opt/atlas/ops → installe /etc/sudoers.d/atlas (re-validé côté
# nœud avant mise en place). Idempotent.
set -euo pipefail

node="${1:?usage: deploy-atlas.sh <ssh-node>}"
here="$(cd "$(dirname "$0")" && pwd)"

echo "▸ Génération du sudoers depuis le registre…"
sudoers="$(python3 "$here/gen-sudoers.py")"
printf '%s' "$sudoers" | visudo -cf - >/dev/null && echo "  ✓ sudoers valide (contrôle local)"

echo "▸ Déploiement des ops dans /opt/atlas/ops sur $node…"
tar -C "$here" -czf - ops \
  | ssh -o BatchMode=yes "$node" 'set -e
      install -d -m 0755 -o root -g root /opt/atlas
      tar -C /opt/atlas -xzf -
      chmod 0755 /opt/atlas/ops/*.sh
      chown -R root:root /opt/atlas/ops
      echo "  ✓ ops déployées : $(ls /opt/atlas/ops | tr "\n" " ")"'

echo "▸ Installation du sudoers sur $node…"
printf '%s' "$sudoers" \
  | ssh -o BatchMode=yes "$node" 'set -e
      tmp=$(mktemp)
      cat > "$tmp"
      visudo -cf "$tmp"
      install -m 0440 -o root -g root "$tmp" /etc/sudoers.d/atlas
      rm -f "$tmp"
      echo "  ✓ /etc/sudoers.d/atlas installé"
      echo "  → droits atlas :"; sudo -l -U atlas 2>/dev/null | sed -n "/NOPASSWD/p" | sed "s/^/    /"'

echo "✓ Déploiement Atlas terminé sur $node."
