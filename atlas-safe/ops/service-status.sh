#!/usr/bin/env bash
# atlas-safe op (RM2050) — état d'un service systemd. Read-only.
# Arg validé par le catalogue (RE_SERVICE) ; `--` par prudence.
set -euo pipefail
svc="${1:?usage: service-status.sh <service>}"
exec systemctl status --no-pager --lines=20 -- "$svc"
