#!/usr/bin/env bash
# atlas-safe op (RM2050) — utilisation disque. Read-only.
set -euo pipefail
exec df -h
