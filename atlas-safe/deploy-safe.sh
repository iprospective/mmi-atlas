#!/usr/bin/env bash
# deploy-safe.sh — déploie l'agent READ-ONLY atlas-safe sur un nœud (RM2050).
#
# atlas-safe = lecture seule, AUCUN droit par défaut. Le cœur Atlas le déclenche par
# SSH `command=` forcé : il ne peut lancer QUE le runner read-only (catalogue vetté).
# Chaque op privilégiée = 1 ligne NOPASSWD générée depuis operations_safe.py.
#
#   ./deploy-safe.sh --node bkp --primary node5 --core-pubkey-file /tmp/core.pub
#
# La clé publique du cœur se génère côté conteneur atlas (user atlas) :
#   ssh-keygen -t ed25519 -f /opt/atlas/.ssh/atlas-safe   (puis copier le .pub)
#
# Idempotent. Sécurité des perms (leçons du 1er déploiement) :
#  - home /opt/atlas-safe = root:atlas-safe 0750 (StrictModes OK + pas d'accès « autre »)
#  - shell /bin/bash REQUIS (la commande forcée s'exécute via le shell) ; l'accès reste
#    borné par command= + mot de passe verrouillé (aucune autre clé).
set -euo pipefail

NODE="" PRIMARY="" PUBFILE="" NODES="node3 node4 node5"
HERE="$(cd "$(dirname "$0")" && pwd)"
ATLAS="$HERE/../atlas"   # catalogue.py + gen-sudoers.py partagés avec le cœur

usage() { sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --node) NODE="$2"; shift 2 ;;
  --primary) PRIMARY="$2"; shift 2 ;;
  --core-pubkey-file) PUBFILE="$2"; shift 2 ;;
  -h|--help) usage 0 ;;
  *) echo "argument inconnu : $1" >&2; usage 1 ;;
esac; done
[[ -n "$NODE" ]] || { echo "--node requis" >&2; usage 1; }
[[ -n "$PUBFILE" && -r "$PUBFILE" ]] || { echo "--core-pubkey-file requis (clé publique du cœur)" >&2; usage 1; }
if [[ -z "$PRIMARY" ]]; then
  for h in $NODES; do
    if ssh "$h" "sudo lxc-ls --running 2>/dev/null | tr ' ' '\n' | grep -qx ${NODE}"; then PRIMARY="$h"; break; fi
  done
  [[ -n "$PRIMARY" ]] || { echo "nœud ${NODE} introuvable (running)" >&2; exit 1; }
fi
echo "▸ Déploiement atlas-safe sur ${NODE} (hôte ${PRIMARY})"

# Staging (umask explicite → pas de dossier group-writable dans le tar).
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
( umask 022
  mkdir -p "$STAGE/ops"
  cp "$ATLAS/catalogue.py" "$ATLAS/gen-sudoers.py" \
     "$HERE/operations_safe.py" "$HERE/atlas-safe-runner.py" "$STAGE/"
  cp "$HERE"/ops/*.sh "$STAGE/ops/"
  printf 'restrict,command="/opt/atlas-safe/atlas-safe-runner.py" %s\n' "$(cat "$PUBFILE")" > "$STAGE/authorized_keys"
  chmod -R go-w "$STAGE" )

tar -C "$STAGE" -czf - . | ssh "$PRIMARY" "sudo lxc-attach -n ${NODE} -- bash -c 'install -d -m0755 -o root -g root /opt/atlas-safe && tar xzf - -C /opt/atlas-safe'"

echo "▸ User, ownership, sudoers, clé command= (dans ${NODE})"
ssh "$PRIMARY" "sudo lxc-attach -n ${NODE} -- bash -s" <<'SETUP'
set -e
# Shell /bin/bash REQUIS pour la commande forcée ; accès borné par command= + pwd verrouillé.
id atlas-safe >/dev/null 2>&1 || useradd --system --home-dir /opt/atlas-safe --no-create-home --shell /bin/bash atlas-safe
usermod -s /bin/bash atlas-safe
cd /opt/atlas-safe
chown -R root:root catalogue.py gen-sudoers.py operations_safe.py atlas-safe-runner.py ops
chmod 0755 atlas-safe-runner.py ops/*.sh; chmod 0644 catalogue.py gen-sudoers.py operations_safe.py
rm -rf __pycache__ ops/__pycache__ 2>/dev/null || true
install -d -m0750 -o atlas-safe -g atlas-safe /opt/atlas-safe/data
# sudoers read-only (1 ligne NOPASSWD par op privilégiée)
ATLAS_OPS_MODULE=operations_safe ATLAS_USER=atlas-safe ATLAS_PROD_OPS_DIR=/opt/atlas-safe/ops python3 gen-sudoers.py > /tmp/atlas-safe.sudoers
visudo -cf /tmp/atlas-safe.sudoers >/dev/null
install -m0440 -o root -g root /tmp/atlas-safe.sudoers /etc/sudoers.d/atlas-safe && rm -f /tmp/atlas-safe.sudoers
# clé command= forcée
install -d -m0700 -o atlas-safe -g atlas-safe /opt/atlas-safe/.ssh
install -m0600 -o atlas-safe -g atlas-safe /opt/atlas-safe/authorized_keys /opt/atlas-safe/.ssh/authorized_keys
rm -f /opt/atlas-safe/authorized_keys
# home 0750 root:atlas-safe (StrictModes OK + aucun accès « autre »)
chown root:atlas-safe /opt/atlas-safe; chmod 0750 /opt/atlas-safe
echo "  ✓ sudo atlas-safe : $(sudo -l -U atlas-safe 2>/dev/null | grep -c NOPASSWD) op(s) read-only"
echo "  ✓ home : $(stat -c '%A %U:%G' /opt/atlas-safe)"
SETUP
echo "✓ atlas-safe déployé sur ${NODE}. Test : ssh -i <clé cœur> atlas-safe@${NODE}.lan 'disk-usage'"
