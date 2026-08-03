#!/usr/bin/env bash
# orch-client — appelle atlas via le canal orchestrateur SSH forced-command (RM2516).
#
# Côté orchestrateur (PM/audit). Encode les arguments en base64(JSON) — robuste aux
# espaces/guillemets — et les envoie à orch_runner.py sur atlas (clé dédiée, sans root).
#
#   orch-client.sh ops
#   orch-client.sh run zbx-host node3.example.net
#   orch-client.sh run --dry-run zbx-ack 123 "message avec espaces"
#
# Config par env : ATLAS_ORCH_HOST (défaut atlas-orch@atlas.example.net),
#                  ATLAS_ORCH_KEY  (défaut ~/.ssh/id_ed25519_karl).
set -euo pipefail
: "${ATLAS_ORCH_HOST:=atlas-orch@atlas.example.net}"
: "${ATLAS_ORCH_KEY:=$HOME/.ssh/id_ed25519_karl}"

[ "$#" -ge 1 ] || { echo "usage: orch-client.sh <ops|run …>" >&2; exit 2; }

payload=$(python3 -c \
  'import base64,json,sys; print(base64.b64encode(json.dumps(sys.argv[1:]).encode()).decode())' \
  "$@")

exec ssh -i "$ATLAS_ORCH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
     "$ATLAS_ORCH_HOST" "atlas $payload"
