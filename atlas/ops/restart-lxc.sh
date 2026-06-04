#!/usr/bin/env bash
# Atlas op (RM1817) — redémarre un conteneur LXC via opensvc. Palier P2 (disruptif).
# Arg <container> déjà validé par le catalogue (RE_CONTAINER).
# On passe par opensvc (`om <svc> restart --local`) pour respecter l'orchestration,
# plutôt que lxc-stop/lxc-start qui la court-circuiterait.
set -euo pipefail
name="${1:?usage: restart-lxc.sh <container>}"
if ! command -v om >/dev/null 2>&1; then
  echo "opensvc (om) introuvable sur ce nœud." >&2
  exit 1
fi
if ! om "$name" print status >/dev/null 2>&1; then
  echo "service opensvc '$name' inconnu sur ce nœud." >&2
  exit 1
fi
om "$name" restart --local
om "$name" print status 2>/dev/null | head -8 || true
