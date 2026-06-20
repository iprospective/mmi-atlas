#!/usr/bin/env bash
# deploy-safe.sh — déploie l'agent READ-ONLY atlas-safe sur un nœud (RM2050).
#
# atlas-safe = lecture seule, AUCUN droit par défaut. Le cœur Atlas le déclenche par
# SSH `command=` forcé : il ne peut lancer QUE le runner read-only (catalogue vetté).
# Chaque op privilégiée = 1 ligne NOPASSWD générée depuis operations_safe.py.
#
# Deux transports :
#   --primary <hôte>   conteneur LXC interne (exec via lxc-attach depuis l'hôte)
#   --remote  <alias>  SSH direct + sudo (HÔTES node3/4/5 ET serveurs CLIENTS)
#
#   ./deploy-safe.sh --node bkp --primary node5 --core-pubkey-file /tmp/core.pub
#   ./deploy-safe.sh --remote node3 --core-pubkey-file /tmp/core.pub
#   ./deploy-safe.sh --node client-web --remote client-x-web --core-pubkey-file /tmp/core.pub
#
# La clé publique du cœur se génère côté conteneur atlas (user atlas) :
#   ssh-keygen -t ed25519 -f /opt/atlas/.ssh/atlas-safe   (puis copier le .pub)
#
# Idempotent. Sécurité des perms : home 0750 root:atlas-safe (StrictModes) ; shell
# /bin/bash REQUIS (commande forcée via le shell), borné par command= + pwd verrouillé.
set -euo pipefail

NODE="" PRIMARY="" REMOTE="" PUBFILE="" NODES="node3 node4 node5"
HERE="$(cd "$(dirname "$0")" && pwd)"
ATLAS="$HERE/../atlas"   # catalogue.py + gen-sudoers.py partagés avec le cœur

usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --node) NODE="$2"; shift 2 ;;
  --primary) PRIMARY="$2"; shift 2 ;;
  --remote) REMOTE="$2"; shift 2 ;;
  --core-pubkey-file) PUBFILE="$2"; shift 2 ;;
  -h|--help) usage 0 ;;
  *) echo "argument inconnu : $1" >&2; usage 1 ;;
esac; done
[[ -n "$PUBFILE" && -r "$PUBFILE" ]] || { echo "--core-pubkey-file requis" >&2; usage 1; }
[[ -n "$REMOTE" || -n "$PRIMARY" || -n "$NODE" ]] || { echo "--remote OU (--node [--primary]) requis" >&2; usage 1; }
[[ -n "$NODE" ]] || NODE="$REMOTE"

# Transport : exécute un bash root lisant un script sur stdin / extrait un tar dans /opt/atlas-safe.
if [[ -n "$REMOTE" ]]; then
  MODE="remote (ssh $REMOTE)"
  root_bash() { ssh "$REMOTE" "sudo bash -s"; }
  extract()   { ssh "$REMOTE" "sudo bash -c 'install -d -m0755 -o root -g root /opt/atlas-safe && tar xzf - -C /opt/atlas-safe'"; }
else
  if [[ -z "$PRIMARY" ]]; then
    for h in $NODES; do
      if ssh "$h" "sudo lxc-ls --running 2>/dev/null | tr ' ' '\n' | grep -qx ${NODE}"; then PRIMARY="$h"; break; fi
    done
    [[ -n "$PRIMARY" ]] || { echo "conteneur ${NODE} introuvable (running)" >&2; exit 1; }
  fi
  MODE="conteneur ${NODE} via lxc-attach ($PRIMARY)"
  root_bash() { ssh "$PRIMARY" "sudo lxc-attach -n ${NODE} -- bash -s"; }
  extract()   { ssh "$PRIMARY" "sudo lxc-attach -n ${NODE} -- bash -c 'install -d -m0755 -o root -g root /opt/atlas-safe && tar xzf - -C /opt/atlas-safe'"; }
fi
echo "▸ Déploiement atlas-safe — ${MODE}"

# Staging (umask explicite → pas de dossier group-writable dans le tar).
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
( umask 022
  mkdir -p "$STAGE/ops"
  cp "$ATLAS/catalogue.py" "$ATLAS/gen-sudoers.py" \
     "$HERE/operations_safe.py" "$HERE/atlas-safe-runner.py" "$STAGE/"
  cp "$HERE"/ops/*.sh "$STAGE/ops/"
  printf 'restrict,command="/opt/atlas-safe/atlas-safe-runner.py" %s\n' "$(cat "$PUBFILE")" > "$STAGE/authorized_keys"
  chmod -R go-w "$STAGE" )

tar -C "$STAGE" -czf - . | extract

echo "▸ User, ownership, sudoers, clé command="
root_bash <<'SETUP'
set -e
id atlas-safe >/dev/null 2>&1 || useradd --system --home-dir /opt/atlas-safe --no-create-home --shell /bin/bash atlas-safe
usermod -s /bin/bash atlas-safe
cd /opt/atlas-safe
chown -R root:root catalogue.py gen-sudoers.py operations_safe.py atlas-safe-runner.py ops
chmod 0755 atlas-safe-runner.py ops/*.sh; chmod 0644 catalogue.py gen-sudoers.py operations_safe.py
rm -rf __pycache__ ops/__pycache__ 2>/dev/null || true
install -d -m0750 -o atlas-safe -g atlas-safe /opt/atlas-safe/data
ATLAS_OPS_MODULE=operations_safe ATLAS_USER=atlas-safe ATLAS_PROD_OPS_DIR=/opt/atlas-safe/ops python3 gen-sudoers.py > /tmp/atlas-safe.sudoers
visudo -cf /tmp/atlas-safe.sudoers >/dev/null
install -m0440 -o root -g root /tmp/atlas-safe.sudoers /etc/sudoers.d/atlas-safe && rm -f /tmp/atlas-safe.sudoers
install -d -m0700 -o atlas-safe -g atlas-safe /opt/atlas-safe/.ssh
install -m0600 -o atlas-safe -g atlas-safe /opt/atlas-safe/authorized_keys /opt/atlas-safe/.ssh/authorized_keys
rm -f /opt/atlas-safe/authorized_keys
chown root:atlas-safe /opt/atlas-safe; chmod 0750 /opt/atlas-safe
echo "  ✓ sudo atlas-safe : $(sudo -l -U atlas-safe 2>/dev/null | grep -c NOPASSWD) op(s) read-only ; home $(stat -c '%A %U:%G' /opt/atlas-safe)"
SETUP
echo "✓ atlas-safe déployé (${NODE})."
