#!/usr/bin/env bash
# atlas-safe op (RM2050) — journal d'une unité (journalctl -u). Read-only.
# Privilégié (root) → NOPASSWD ciblé sur CE script. Args validés par le catalogue :
# <unit∈RE_SERVICE> [lines∈1..500]. `--` ferme l'option-parsing (anti flag libre).
set -euo pipefail
unit="${1:?usage: journal.sh <unit> [lines]}"
lines="${2:-80}"
exec journalctl --no-pager -n "$lines" -u "$unit" --
