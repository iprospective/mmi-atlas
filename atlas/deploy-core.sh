#!/usr/bin/env bash
# deploy-core.sh — déploie le CŒUR Atlas dans son conteneur (RM2039).
#
# Complément de deploy-bot.sh. Installe le daemon cœur sous le user dédié `atlas`,
# migre le sudoers (atlas-bot → atlas), crée le groupe `atlas-ifaces` (accès socket),
# et démarre le service. À lancer APRÈS deploy-bot.sh (le bot doit exister).
#
# Sécurité : le sudo des ops privilégiées vit sur le CŒUR (`atlas`), pas sur les
# interfaces. `atlas-bot` perd tout NOPASSWD (relais pur). Code owned root (RO),
# `data/` (audit) writable par le cœur.
#
#   ./deploy-core.sh --container atlas [--primary node5]
#
# Idempotent / re-jouable.
set -euo pipefail

CONTAINER="" PRIMARY="" NODES="node3 node4 node5"
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --container) CONTAINER="$2"; shift 2 ;;
  --primary)   PRIMARY="$2"; shift 2 ;;
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
echo "▸ Déploiement cœur Atlas dans ${CONTAINER} (hôte ${PRIMARY})"

# Sudoers du cœur (user atlas) généré depuis le registre.
echo "▸ Sudoers (user atlas) depuis operations.py"
ATLAS_USER=atlas ATLAS_PROD_OPS_DIR=/opt/atlas/ops python3 "$HERE/gen-sudoers.py" > /tmp/atlas-core.sudoers
visudo -cf /tmp/atlas-core.sudoers >/dev/null && echo "  ✓ sudoers valide (local)"

# Code cœur + unit, poussés.
tar czf - -C "$HERE" atlas-core.py atlas_client.py | ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- tar xzf - -C /opt/atlas"
cat "$HERE/atlas-core.service" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/etc/systemd/system/atlas-core.service >/dev/null"
cat /tmp/atlas-core.sudoers    | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/tmp/atlas-core.sudoers >/dev/null"

echo "▸ User/groupe, ownership, sudoers, service (dans ${CONTAINER})"
ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- bash -s" <<'SH'
set -e
getent group atlas-ifaces >/dev/null || groupadd --system atlas-ifaces
id atlas >/dev/null 2>&1 || useradd --system --home-dir /opt/atlas --no-create-home --shell /usr/sbin/nologin atlas
usermod -aG atlas-ifaces atlas
id atlas-bot >/dev/null 2>&1 && usermod -aG atlas-ifaces atlas-bot || true
cd /opt/atlas
chown root:root atlas-core.py atlas_client.py; chmod 0644 atlas-core.py atlas_client.py
install -d -m 0750 -o atlas -g atlas /opt/atlas/data
rm -rf __pycache__ ops/__pycache__ 2>/dev/null || true
# sudoers : cœur IN, bot OUT (le bot ne sudoe plus)
visudo -cf /tmp/atlas-core.sudoers >/dev/null
install -m 0440 -o root -g root /tmp/atlas-core.sudoers /etc/sudoers.d/atlas && rm -f /tmp/atlas-core.sudoers
rm -f /etc/sudoers.d/atlas-bot
systemctl daemon-reload
systemctl enable --now atlas-core.service >/dev/null 2>&1 || true
echo "  ✓ core: $(systemctl is-active atlas-core) ; socket: $(ls -la /run/atlas/atlas.sock 2>/dev/null | awk '{print $1,$3,$4}')"
echo "  ✓ sudo atlas (cœur): $(sudo -l -U atlas 2>/dev/null | grep -c NOPASSWD) ops ; atlas-bot: $(sudo -l -U atlas-bot 2>/dev/null | grep -c NOPASSWD) (doit être 0)"
SH
echo "✓ Cœur déployé. (Re)démarrer le bot pour qu'il rejoigne le groupe atlas-ifaces : systemctl restart atlas-bot"
