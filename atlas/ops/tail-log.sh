#!/usr/bin/env bash
# Atlas op (RM1817) — affiche la fin d'un log système. Palier P0 (lecture seule).
# Args validés par le catalogue : <log∈{syslog,auth,kern,dpkg}> [lines].
# La liste blanche ci-dessous DOIT rester alignée sur les choices du registre.
set -euo pipefail
key="${1:?usage: tail-log.sh <syslog|auth|kern|dpkg> [lines]}"
lines="${2:-50}"
case "$key" in
  syslog) f="/var/log/syslog" ;;
  auth)   f="/var/log/auth.log" ;;
  kern)   f="/var/log/kern.log" ;;
  dpkg)   f="/var/log/dpkg.log" ;;
  *) echo "log inconnu : $key" >&2; exit 2 ;;
esac
[ -r "$f" ] || { echo "log absent ou illisible : $f" >&2; exit 1; }
exec tail -n "$lines" -- "$f"
