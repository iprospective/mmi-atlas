#!/usr/bin/env bash
# Atlas op (RM1817) — redémarre un service systemd / pool FPM. Palier P2.
# Arg <service> déjà validé par le catalogue (RE_SERVICE) ; `--` par prudence.
set -euo pipefail
svc="${1:?usage: restart-service.sh <service>}"
systemctl restart -- "$svc"
systemctl --no-pager --lines=10 status -- "$svc"
