#!/usr/bin/env bash
# Atlas op de référence (RM1816) — état d'un service systemd. Read-only, palier P0.
# L'argument est déjà validé par le catalogue (RE_SERVICE) ; `--` par prudence.
set -euo pipefail
svc="${1:?usage: service-status.sh <service>}"
exec systemctl status --no-pager --lines=20 -- "$svc"
