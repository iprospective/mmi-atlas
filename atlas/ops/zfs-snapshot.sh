#!/usr/bin/env bash
# Atlas op (RM1817) — snapshot ZFS d'un dataset. Palier P1 (additif, réversible).
# Args validés par le catalogue : <dataset> [<label>]. Le snapshot est horodaté.
set -euo pipefail
dataset="${1:?usage: zfs-snapshot.sh <dataset> [label]}"
label="${2:-atlas}"
snap="${dataset}@${label}-$(date +%Y%m%d-%H%M%S)"
zfs snapshot -- "$snap"
echo "snapshot créé : $snap"
