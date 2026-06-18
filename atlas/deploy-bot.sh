#!/usr/bin/env bash
# deploy-bot.sh — déploie le BOT Atlas dans son conteneur (RM1848).
#
# Complément de deploy-atlas.sh (qui, lui, pousse ops+sudoers sur un NŒUD pour le
# user SSH `atlas`, RM1817). Ici on installe le bot lui-même dans son conteneur :
# code + unit systemd + user dédié `atlas-bot` + sudoers LOCAL (atlas-bot) pour les
# ops privilégiées exécutées SUR ce conteneur.
#
# Propriété (sécurité sudo) : le code et `ops/` appartiennent à **root**, en
# lecture seule pour `atlas-bot` (sinon le bot pourrait réécrire un script lancé en
# root via NOPASSWD = évasion). Seul `data/` (audit JSONL) est writable par le bot ;
# `.env` est root:atlas-bot 0640 (secret, lu par le bot + systemd EnvironmentFile).
#
# Le `.env` n'est JAMAIS écrasé s'il existe (le token vit là, hors versionning).
#
#   ./deploy-bot.sh --container atlas [--primary node5]
#
# Idempotent / re-jouable. NE démarre PAS le service (token à remplir d'abord).
set -euo pipefail

CONTAINER="" PRIMARY="" BOT_USER="atlas-bot"
NODES="node3 node4 node5"
HERE="$(cd "$(dirname "$0")" && pwd)"
CODE=(atlas-bot.py catalogue.py operations.py)   # modules ; + ops/ traité à part

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --container) CONTAINER="$2"; shift 2 ;;
  --primary)   PRIMARY="$2"; shift 2 ;;
  --user)      BOT_USER="$2"; shift 2 ;;
  -h|--help)   usage 0 ;;
  *) echo "argument inconnu : $1" >&2; usage 1 ;;
esac; done
[[ -n "$CONTAINER" ]] || { echo "--container requis" >&2; usage 1; }

# Localise l'hôte actif du conteneur (sauf si --primary fourni).
if [[ -z "$PRIMARY" ]]; then
  for h in $NODES; do
    if ssh "$h" "sudo lxc-ls --running 2>/dev/null | tr ' ' '\n' | grep -qx ${CONTAINER}"; then PRIMARY="$h"; break; fi
  done
  [[ -n "$PRIMARY" ]] || { echo "conteneur ${CONTAINER} introuvable (running)" >&2; exit 1; }
fi
echo "▸ Déploiement bot Atlas dans ${CONTAINER} (hôte ${PRIMARY}, user ${BOT_USER})"

inct() { ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- bash -s"; }

# 1) Code + ops → /opt/atlas (root-owned). tar piped via lxc-attach.
echo "▸ Code + ops → /opt/atlas (root:root, RO)"
ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- install -d -m 0755 -o root -g root /opt/atlas"
tar -C "$HERE" -czf - "${CODE[@]}" ops | ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- tar xzf - -C /opt/atlas"

# 2) Unit systemd + 3) user + deps + 4) ownership + 5) sudoers atlas-bot
echo "▸ Génération du sudoers (${BOT_USER}) depuis operations.py"
ATLAS_USER="$BOT_USER" ATLAS_PROD_OPS_DIR=/opt/atlas/ops python3 "$HERE/gen-sudoers.py" > /tmp/atlas-bot.sudoers
visudo -cf /tmp/atlas-bot.sudoers >/dev/null && echo "  ✓ sudoers valide (local)"
cat "$HERE/atlas-bot.service" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/etc/systemd/system/atlas-bot.service >/dev/null"
cat /tmp/atlas-bot.sudoers     | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/tmp/atlas-bot.sudoers >/dev/null"
# .env : déposer un template UNIQUEMENT s'il n'existe pas (ne jamais écraser le token)
ssh "$PRIMARY" "sudo test -f /zfs/lxc/${CONTAINER}/opt/atlas/.env" \
  || cat "$HERE/.env.example" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/opt/atlas/.env >/dev/null"

echo "▸ User ${BOT_USER}, deps, ownership, sudoers, enable (dans ${CONTAINER})"
BOT_USER="$BOT_USER" inct <<'SH'
set -e
export DEBIAN_FRONTEND=noninteractive
id "${BOT_USER:-atlas-bot}" >/dev/null 2>&1 || useradd --system --home-dir /opt/atlas --shell /usr/sbin/nologin "${BOT_USER:-atlas-bot}"
dpkg -s python3-requests >/dev/null 2>&1 || { apt-get update -qq; apt-get install -y --no-install-recommends python3-requests >/dev/null; }
cd /opt/atlas
# code + ops → root (RO pour le bot) ; data → bot (writable) ; .env → root:bot 0640
chown root:root /opt/atlas atlas-bot.py catalogue.py operations.py
chown -R root:root ops; chmod 0755 /opt/atlas ops; chmod 0644 *.py; chmod 0755 ops/*.sh
install -d -m 0750 -o "${BOT_USER:-atlas-bot}" -g "${BOT_USER:-atlas-bot}" /opt/atlas/data
chown root:"${BOT_USER:-atlas-bot}" /opt/atlas/.env; chmod 0640 /opt/atlas/.env
rm -rf __pycache__ ops/__pycache__ 2>/dev/null || true
# sudoers (re-validé côté cible)
visudo -cf /tmp/atlas-bot.sudoers >/dev/null
install -m 0440 -o root -g root /tmp/atlas-bot.sudoers /etc/sudoers.d/atlas-bot && rm -f /tmp/atlas-bot.sudoers
systemctl daemon-reload
systemctl enable atlas-bot.service >/dev/null 2>&1 || true
echo "  ✓ sudo ${BOT_USER:-atlas-bot} :"; sudo -l -U "${BOT_USER:-atlas-bot}" 2>/dev/null | grep NOPASSWD | sed 's/^/    /'
SH

echo "✓ Bot déployé dans ${CONTAINER}."
echo "  Reste à la main : remplir /opt/atlas/.env (token/whitelist/hash) puis 'systemctl start atlas-bot'."
