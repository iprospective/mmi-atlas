#!/usr/bin/env bash
# package-atlas-client.sh — installe l'agent cible **atlas-client** sur UN nœud (RM2042).
#
# Recadre + remplace provision-atlas.sh (RM1815) ET deploy-atlas.sh (RM1817) sous
# l'identité renommée **atlas-client** (le user `atlas` est désormais le CŒUR, sur son
# conteneur — on lève l'ambiguïté). Paquet déployable, idempotent, multi-tenant
# (infra interne ET machines clients) :
#
#   user atlas-client (nologin→/bin/bash pour la commande forcée) + ops vetted owned
#   root (RO) + sudoers ciblé (gen-sudoers) + runner SSH `command=` forcé + atlas-cli
#   LOCAL (runner du nœud). Cloisonnement : 1 clé du cœur par périmètre/ client
#   (registre RM2050) ; un client ne voit jamais un autre.
#
#   ./package-atlas-client.sh <ssh-node> [--lxc <name>] [--ssh-key "<pubkey du cœur>"] [--dry-run]
#
# --dry-run (DÉFAUT prudent : non, mais recommandé en 1re passe) montre le plan + le
# sudoers généré sans rien changer. Sécurité prod : sur la flotte existante, lancer
# d'abord en --dry-run, valider, puis sans.
set -euo pipefail

ATLAS_USER="atlas-client"
ATLAS_HOME="/var/lib/atlas-client"
CODE_DIR="/opt/atlas-client"
SUDOERS_FILE="/etc/sudoers.d/atlas-client"
node="" lxc="" ssh_key="" DRY=0
HERE="$(cd "$(dirname "$0")" && pwd)"
# Catalogue ACTING (operations.py) + runtime + atlas-cli local, poussés sur le nœud.
CODE=(catalogue.py operations.py atlas-cli.py atlas-client-runner.py)

usage() { sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --lxc)     lxc="${2:?--lxc nécessite un nom}"; shift 2 ;;
  --ssh-key) ssh_key="${2:-}"; shift 2 ;;
  --dry-run) DRY=1; shift ;;
  -h|--help) usage 0 ;;
  -*) echo "option inconnue : $1" >&2; usage 2 ;;
  *) node="$1"; shift ;;
esac; done
[[ -n "$node" ]] || { echo "usage: package-atlas-client.sh <ssh-node> [--lxc <c>] [--ssh-key <k>] [--dry-run]" >&2; usage 2; }
tag="${lxc:+$lxc@}$node"
[[ "$DRY" = 1 ]] && echo "▸▸ DRY-RUN — aucune modification sur $tag" || echo "▸▸ Installation atlas-client sur $tag"

# Exécute un script bash sur la cible (hôte, ou conteneur via lxc-attach). En dry-run,
# n'exécute QUE les commandes de lecture (préfixées par l'appelant) — ici on affiche.
remote_exec() {
  if [[ "$DRY" = 1 ]]; then echo "  [dry-run] script cible non exécuté ($(wc -l <<<"$1") lignes)"; return 0; fi
  if [[ -n "$lxc" ]]; then printf '%s' "$1" | ssh -o BatchMode=yes "$node" "sudo lxc-attach -n '$lxc' -- bash -s"
  else printf '%s' "$1" | ssh -o BatchMode=yes "$node" "sudo bash -s"; fi
}
push_file() {
  if [[ "$DRY" = 1 ]]; then echo "  [dry-run] push $1 → cible:$2"; return 0; fi
  if [[ -n "$lxc" ]]; then ssh -o BatchMode=yes "$node" "sudo lxc-attach -n '$lxc' -- tee '$2' >/dev/null" < "$1"
  else ssh -o BatchMode=yes "$node" "sudo tee '$2' >/dev/null" < "$1"; fi
}

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# ── 1. Sudoers ciblé (généré depuis operations.py pour le user/ops renommés) ──
echo "▸ Sudoers atlas-client (depuis operations.py)…"
ATLAS_USER="$ATLAS_USER" ATLAS_PROD_OPS_DIR="$CODE_DIR/ops" ATLAS_OPS_MODULE=operations \
  python3 "$HERE/gen-sudoers.py" > "$tmp/atlas-client.sudoers"
visudo -cf "$tmp/atlas-client.sudoers" >/dev/null && echo "  ✓ sudoers valide (contrôle local)"
[[ "$DRY" = 1 ]] && { echo "  ── sudoers généré ──"; sed 's/^/    /' "$tmp/atlas-client.sudoers"; }

# ── 2. Paquet code + ops ──
tar -C "$HERE" -czf "$tmp/pkg.tgz" "${CODE[@]}" ops
push_file "$tmp/pkg.tgz" /tmp/atlas-client-pkg.tgz
push_file "$tmp/atlas-client.sudoers" /tmp/atlas-client.sudoers

# ── 3. Provision user + pose code/sudoers/ssh/symlink (idempotent) ──
SCRIPT=$(cat <<SH
set -e
U="$ATLAS_USER"; HOME_DIR="$ATLAS_HOME"; CODE="$CODE_DIR"; SUD="$SUDOERS_FILE"
# user : système, /bin/bash REQUIS pour la commande forcée SSH (sinon login refusé).
id "\$U" >/dev/null 2>&1 || useradd --system --create-home --home-dir "\$HOME_DIR" \\
  --shell /bin/bash --comment "Atlas client agent (RM2042)" "\$U"
install -d -m 0750 -o root -g "\$U" "\$HOME_DIR"
# code/ops → root (RO pour l'agent : il ne peut pas réécrire un script lancé en sudo) ;
# data/ → agent (audit writable).
install -d -m 0755 -o root -g root "\$CODE"
tar -C "\$CODE" -xzf /tmp/atlas-client-pkg.tgz
chown -R root:root "\$CODE"
chmod 0755 "\$CODE" "\$CODE/ops" "\$CODE"/ops/*.sh "\$CODE/atlas-cli.py" "\$CODE/atlas-client-runner.py"
chmod 0644 "\$CODE/catalogue.py" "\$CODE/operations.py"
install -d -m 0750 -o "\$U" -g "\$U" "\$CODE/data"
rm -f /tmp/atlas-client-pkg.tgz
# sudoers (re-validé côté cible avant pose).
visudo -cf /tmp/atlas-client.sudoers
install -m 0440 -o root -g root /tmp/atlas-client.sudoers "\$SUD"
rm -f /tmp/atlas-client.sudoers
# atlas-cli local sur le PATH (runner du nœud).
ln -sf "\$CODE/atlas-cli.py" /usr/local/bin/atlas-client-cli
echo "  ✓ user \$U ; code \$CODE (root:RO) ; sudoers \$SUD :"
sudo -l -U "\$U" 2>/dev/null | sed -n "/NOPASSWD/p" | sed "s/^/    /"
SH
)
echo "▸ Provision user + code + sudoers sur $tag…"
remote_exec "$SCRIPT"

# ── 4. Clé SSH du cœur → command= forcé vers le runner (frontière 2) ──
if [[ -n "$ssh_key" ]]; then
  echo "▸ authorized_keys (command= forcé vers le runner) sur $tag…"
  KEY_SCRIPT=$(cat <<SH
set -e
U="$ATLAS_USER"; HOME_DIR="$ATLAS_HOME"
SSH_DIR="\$HOME_DIR/.ssh"; AUTH="\$SSH_DIR/authorized_keys"
install -d -m 0700 -o "\$U" -g "\$U" "\$SSH_DIR"
LINE='restrict,command="$CODE_DIR/atlas-client-runner.py" $ssh_key'
touch "\$AUTH"
if grep -qF '$ssh_key' "\$AUTH"; then echo "  ✓ clé déjà autorisée (command= forcé)";
else printf '%s\n' "\$LINE" >> "\$AUTH"; echo "  ✓ clé du cœur ajoutée (restrict + command= forcé)"; fi
chown "\$U:\$U" "\$AUTH"; chmod 0600 "\$AUTH"
SH
)
  remote_exec "$KEY_SCRIPT"
else
  echo "▸ (pas de --ssh-key : authorized_keys non touché ; passe la clé du cœur pour activer le dispatch)"
fi

echo "✓ atlas-client ${DRY:+(plan) }installé sur $tag."
[[ "$DRY" = 1 ]] && echo "  → relance sans --dry-run pour appliquer."
