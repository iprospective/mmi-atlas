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
tar czf - -C "$HERE" atlas-core.py atlas_client.py decision.py policy.py atlas_ai.py safe_dispatch.py client_dispatch.py redact.py zabbix_api.py zabbix_ops.py orch_runner.py access.py atlas-cli.py catalogue.py operations.py ops load-keys.sh | ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- tar xzf - -C /opt/atlas"
cat "$HERE/atlas-core.service"      | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/etc/systemd/system/atlas-core.service >/dev/null"
cat "$HERE/atlas-ssh-agent.service" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/etc/systemd/system/atlas-ssh-agent.service >/dev/null"
cat /tmp/atlas-core.sudoers    | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/tmp/atlas-core.sudoers >/dev/null"
# core.env (plafond d'autonomie) : déposer le template UNIQUEMENT s'il n'existe pas.
ssh "$PRIMARY" "sudo test -f /zfs/lxc/${CONTAINER}/opt/atlas/core.env" \
  || cat "$HERE/core.env.example" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/opt/atlas/core.env >/dev/null"

echo "▸ User/groupe, ownership, sudoers, service (dans ${CONTAINER})"
ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- bash -s" <<'SH'
set -e
getent group atlas-ifaces >/dev/null || groupadd --system atlas-ifaces
id atlas >/dev/null 2>&1 || useradd --system --home-dir /opt/atlas --no-create-home --shell /usr/sbin/nologin atlas
usermod -aG atlas-ifaces atlas
id atlas-bot >/dev/null 2>&1 && usermod -aG atlas-ifaces atlas-bot || true
# atlas-cli : opérateur central (RM2041/RM2092) — identité P2 dans les droits partagés,
# accès socket via atlas-ifaces. `sudo runuser -u atlas-cli -- atlas-cli run …`.
id atlas-cli >/dev/null 2>&1 || useradd --system --home-dir /opt/atlas --no-create-home --shell /usr/sbin/nologin atlas-cli
usermod -aG atlas-ifaces atlas-cli
cd /opt/atlas
chown root:root atlas-core.py atlas_client.py decision.py policy.py atlas_ai.py safe_dispatch.py client_dispatch.py redact.py zabbix_api.py zabbix_ops.py orch_runner.py access.py atlas-cli.py catalogue.py operations.py load-keys.sh
chmod 0644 atlas-core.py atlas_client.py decision.py policy.py atlas_ai.py safe_dispatch.py client_dispatch.py redact.py zabbix_api.py zabbix_ops.py orch_runner.py access.py catalogue.py operations.py
chmod 0755 load-keys.sh atlas-cli.py
chown -R root:root ops; chmod 0755 ops; chmod 0755 ops/*.sh
# atlas-cli (RM2041) accessible sur le PATH des opérateurs (shell sur le conteneur atlas).
ln -sf /opt/atlas/atlas-cli.py /usr/local/bin/atlas-cli
install -d -m 0750 -o atlas -g atlas /opt/atlas/data
chown -R atlas:atlas /opt/atlas/data   # audit/état writable par le cœur (auto-répare)
[ -f /opt/atlas/core.env ] && chown root:atlas /opt/atlas/core.env && chmod 0640 /opt/atlas/core.env || true
rm -rf __pycache__ ops/__pycache__ 2>/dev/null || true
# sudoers : cœur IN, bot OUT (le bot ne sudoe plus)
visudo -cf /tmp/atlas-core.sudoers >/dev/null
install -m 0440 -o root -g root /tmp/atlas-core.sudoers /etc/sudoers.d/atlas && rm -f /tmp/atlas-core.sudoers
rm -f /etc/sudoers.d/atlas-bot
systemctl daemon-reload
systemctl enable --now atlas-ssh-agent.service >/dev/null 2>&1 || true   # agent SSH (RM2058)
systemctl enable atlas-core.service >/dev/null 2>&1 || true
systemctl restart atlas-core.service   # restart (pas enable --now) : recharge le code même si déjà actif
echo "  ✓ core: $(systemctl is-active atlas-core) ; socket: $(ls -la /run/atlas/atlas.sock 2>/dev/null | awk '{print $1,$3,$4}')"
echo "  ✓ sudo atlas (cœur): $(sudo -l -U atlas 2>/dev/null | grep -c NOPASSWD) ops ; atlas-bot: $(sudo -l -U atlas-bot 2>/dev/null | grep -c NOPASSWD) (doit être 0)"
SH
echo "✓ Cœur déployé. (Re)démarrer le bot pour qu'il rejoigne le groupe atlas-ifaces : systemctl restart atlas-bot"
