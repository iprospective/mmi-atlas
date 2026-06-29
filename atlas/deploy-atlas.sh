#!/usr/bin/env bash
# ⚠ DÉPRÉCIÉ (RM2042) — remplacé par package-atlas-client.sh (identité renommée
#   `atlas-client`, paquet unifié user+ops+sudoers+runner+atlas-cli local, --dry-run).
#   Conservé pour référence ; ne plus l'utiliser pour de nouveaux nœuds.
#
# deploy-atlas.sh — déploie les opérations du catalogue + le sudoers sur une cible
# (RM1817). À lancer depuis le repo (orchestration). La cible doit être root/sudo
# et le user `atlas` doit déjà exister (provision-atlas.sh, RM1815).
#
#   ./deploy-atlas.sh <ssh-node>                # hôte ssh-joignable (node3/4/5…)
#   ./deploy-atlas.sh <ssh-host> --lxc <name>   # conteneur LXC via son hôte
#
# Étapes (idempotentes) : génère le sudoers depuis le registre → valide localement
# (visudo -c) → pousse ops/ dans /opt/atlas/ops → installe /etc/sudoers.d/atlas
# (re-validé côté cible avant mise en place).
set -euo pipefail

node=""; lxc=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --lxc) lxc="${2:?--lxc nécessite un nom}"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "option inconnue : $1" >&2; exit 2 ;;
    *) node="$1"; shift ;;
  esac
done
[[ -n "$node" ]] || { echo "usage: deploy-atlas.sh <ssh-node> [--lxc <container>]" >&2; exit 2; }

here="$(cd "$(dirname "$0")" && pwd)"
tag="${lxc:+$lxc@}$node"

# Exécute un script bash sur la cible (hôte, ou conteneur via lxc-attach).
remote_exec() {
  if [[ -n "$lxc" ]]; then
    printf '%s' "$1" | ssh -o BatchMode=yes "$node" "lxc-attach -n '$lxc' -- bash -s"
  else
    printf '%s' "$1" | ssh -o BatchMode=yes "$node" "bash -s"
  fi
}
# Copie un fichier local vers la cible.
push_file() {
  if [[ -n "$lxc" ]]; then
    ssh -o BatchMode=yes "$node" "lxc-attach -n '$lxc' -- tee '$2' >/dev/null" < "$1"
  else
    ssh -o BatchMode=yes "$node" "tee '$2' >/dev/null" < "$1"
  fi
}

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

echo "▸ Génération du sudoers depuis le registre…"
python3 "$here/gen-sudoers.py" > "$tmp/atlas.sudoers"
visudo -cf "$tmp/atlas.sudoers" >/dev/null && echo "  ✓ sudoers valide (contrôle local)"
tar -C "$here" -czf "$tmp/ops.tgz" ops

echo "▸ Déploiement des ops dans /opt/atlas/ops sur $tag…"
push_file "$tmp/ops.tgz" /tmp/atlas-ops.tgz
remote_exec '
set -e
install -d -m 0755 -o root -g root /opt/atlas
tar -C /opt/atlas -xzf /tmp/atlas-ops.tgz
chmod 0755 /opt/atlas/ops/*.sh
chown -R root:root /opt/atlas/ops
rm -f /tmp/atlas-ops.tgz
printf "  ✓ ops : %s\n" "$(ls /opt/atlas/ops | tr "\n" " ")"
'

echo "▸ Installation du sudoers sur $tag…"
push_file "$tmp/atlas.sudoers" /tmp/atlas-sudoers
remote_exec '
set -e
visudo -cf /tmp/atlas-sudoers
install -m 0440 -o root -g root /tmp/atlas-sudoers /etc/sudoers.d/atlas
rm -f /tmp/atlas-sudoers
echo "  ✓ /etc/sudoers.d/atlas installé ; droits atlas :"
sudo -l -U atlas 2>/dev/null | sed -n "/NOPASSWD/p" | sed "s/^/    /"
'

echo "✓ Déploiement Atlas terminé sur $tag."
