#!/usr/bin/env bash
# atlas-safe op (RM2050) — fin d'un log système NOMMÉ, filtre optionnel. Read-only.
# Privilégié (root) → NOPASSWD ciblé. Args validés par le catalogue :
#   <log∈{syslog,auth,kern,daemon,dpkg}> [lines∈1..500] [pattern (RE_GREP)]
# Le nom → chemin est figé ici (JAMAIS un chemin libre = pas de lecture de /etc/shadow).
# Le motif est passé en CHAÎNE FIXE (grep -F --) → ni injection ni ReDoS.
set -euo pipefail
key="${1:?usage: tail-log.sh <syslog|auth|kern|daemon|dpkg> [lines] [pattern]}"
lines="${2:-80}"
pattern="${3:-}"
case "$key" in
  syslog) f="/var/log/syslog" ;;
  auth)   f="/var/log/auth.log" ;;
  kern)   f="/var/log/kern.log" ;;
  daemon) f="/var/log/daemon.log" ;;
  dpkg)   f="/var/log/dpkg.log" ;;
  *) echo "log inconnu : $key" >&2; exit 2 ;;
esac
[ -r "$f" ] || { echo "log absent ou illisible : $f" >&2; exit 1; }
if [ -n "$pattern" ]; then
  # filtre en chaîne fixe sur les N dernières lignes (grep ne doit pas faire échouer si 0 match)
  tail -n "$lines" -- "$f" | grep -F -- "$pattern" || true
else
  exec tail -n "$lines" -- "$f"
fi
