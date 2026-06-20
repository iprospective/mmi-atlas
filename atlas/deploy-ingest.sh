#!/usr/bin/env bash
# deploy-ingest.sh — déploie l'endpoint d'INGESTION Atlas dans son conteneur (RM1813).
#
# Interface NON privilégiée (comme le bot) : reçoit les webhooks monitoring, vérifie
# le HMAC, relaie au cœur via le socket. AUCUN sudoers ici (l'ingest n'exécute jamais
# d'op — c'est le cœur qui décide+exécute). User dédié `atlas-ingest`, membre de
# `atlas-ifaces` (accès socket). Code root-owned (RO) ; `ingest.env` (secret) root:user 0640.
#
# Le `ingest.env` n'est JAMAIS écrasé s'il existe (le secret HMAC vit là).
# À lancer APRÈS deploy-core.sh (le groupe atlas-ifaces + le cœur doivent exister).
#
#   ./deploy-ingest.sh --container atlas [--primary node5]
#
# Idempotent. NE démarre PAS le service (secret + bind vrack à renseigner d'abord).
set -euo pipefail

CONTAINER="" PRIMARY="" ING_USER="atlas-ingest"
NODES="node3 node4 node5"
HERE="$(cd "$(dirname "$0")" && pwd)"
CODE=(atlas-ingest.py atlas_client.py)

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --container) CONTAINER="$2"; shift 2 ;;
  --primary)   PRIMARY="$2"; shift 2 ;;
  --user)      ING_USER="$2"; shift 2 ;;
  -h|--help)   usage 0 ;;
  *) echo "argument inconnu : $1" >&2; usage 1 ;;
esac; done
[[ -n "$CONTAINER" ]] || { echo "--container requis" >&2; usage 1; }
if [[ -z "$PRIMARY" ]]; then
  for h in $NODES; do
    if ssh "$h" "sudo lxc-ls --running 2>/dev/null | tr ' ' '\n' | grep -qx ${CONTAINER}"; then PRIMARY="$h"; break; fi
  done
  [[ -n "$PRIMARY" ]] || { echo "conteneur ${CONTAINER} introuvable (running)" >&2; exit 1; }
fi
echo "▸ Déploiement ingest Atlas dans ${CONTAINER} (hôte ${PRIMARY}, user ${ING_USER})"

# Code → /opt/atlas (root-owned).
tar -C "$HERE" -czf - "${CODE[@]}" | ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- tar xzf - -C /opt/atlas"
cat "$HERE/atlas-ingest.service" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/etc/systemd/system/atlas-ingest.service >/dev/null"
ssh "$PRIMARY" "sudo test -f /zfs/lxc/${CONTAINER}/opt/atlas/ingest.env" \
  || cat "$HERE/ingest.env.example" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/opt/atlas/ingest.env >/dev/null"

echo "▸ User ${ING_USER}, ownership, service (dans ${CONTAINER})"
ING_USER="$ING_USER" ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- bash -s" <<'SH'
set -e
U="${ING_USER:-atlas-ingest}"
getent group atlas-ifaces >/dev/null || groupadd --system atlas-ifaces
id "$U" >/dev/null 2>&1 || useradd --system --home-dir /opt/atlas --no-create-home --shell /usr/sbin/nologin "$U"
usermod -aG atlas-ifaces "$U"
cd /opt/atlas
chown root:root atlas-ingest.py atlas_client.py; chmod 0644 atlas-ingest.py atlas_client.py
chown root:"$U" /opt/atlas/ingest.env; chmod 0640 /opt/atlas/ingest.env
rm -rf __pycache__ 2>/dev/null || true
systemctl daemon-reload
systemctl enable atlas-ingest.service >/dev/null 2>&1 || true
echo "  ✓ user $U dans atlas-ifaces ; service $(systemctl is-enabled atlas-ingest 2>/dev/null)"
SH
echo "✓ Ingest déployé. Reste à la main : remplir /opt/atlas/ingest.env (secret HMAC + bind vrack) puis 'systemctl start atlas-ingest'."
