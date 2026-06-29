#!/usr/bin/env bash
# ⚠ DÉPRÉCIÉ (RM2042) — remplacé par package-atlas-client.sh (user renommé
#   `atlas` → `atlas-client`, + ops/sudoers/runner/atlas-cli local en un paquet).
#   Conservé pour référence ; ne plus l'utiliser pour de nouveaux nœuds.
#
# provision-atlas.sh — Provisionne le user d'exécution privilégié d'Atlas sur UN
# nœud (hôte ou conteneur LXC). Idempotent, sans dépendance (pas d'Ansible — cf.
# RM1815 / RM1118). À lancer en root sur chaque nœud du parc.
#
#   sudo ./provision-atlas.sh [--ssh-key "<clé publique authorized_keys>"]
#
# Crée/maintient :
#   - l'utilisateur système `atlas` (sans mot de passe, shell restreint)
#   - /etc/sudoers.d/atlas — VIDE par défaut (moindre privilège). Les droits
#     ciblés par opération seront ajoutés par le catalogue (RM1816), un script =
#     une ligne NOPASSWD sur un chemin absolu. JAMAIS de sudo blanc.
#   - ~atlas/.ssh/authorized_keys avec restrictions (si --ssh-key fourni)
#
# Ré-exécutable sans effet de bord : ne réécrit que ce qui diffère.
set -euo pipefail

ATLAS_USER="atlas"
ATLAS_HOME="/var/lib/atlas"
SUDOERS_FILE="/etc/sudoers.d/atlas"
SSH_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-key) SSH_KEY="${2:-}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Argument inconnu : $1" >&2; exit 2 ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Ce script doit être lancé en root." >&2
  exit 1
fi

log() { printf '  %s\n' "$*"; }

# ── 1. Utilisateur système `atlas` ───────────────────────────────────────────
if id "$ATLAS_USER" &>/dev/null; then
  log "user $ATLAS_USER : déjà présent"
else
  useradd --system --create-home --home-dir "$ATLAS_HOME" \
          --shell /usr/sbin/nologin --comment "Atlas privileged ops" "$ATLAS_USER"
  log "user $ATLAS_USER : créé (home=$ATLAS_HOME, shell=nologin)"
fi

# ── 2. sudoers.d/atlas — squelette verrouillé (moindre privilège) ─────────────
# Par défaut AUCUN droit : le catalogue (RM1816) ajoutera des lignes ciblées du
# type :  atlas ALL=(root) NOPASSWD: /opt/atlas/ops/<operation>.sh ""
TMP_SUDOERS="$(mktemp)"
cat > "$TMP_SUDOERS" <<EOF
# Managed by provision-atlas.sh — NE PAS éditer à la main.
# Droits ciblés par opération ajoutés par le catalogue Atlas (RM1816).
# Aucun droit pour l'instant (moindre privilège).
EOF
# visudo -c valide la syntaxe avant toute mise en place (un sudoers cassé =
# sudo HS sur la machine).
if visudo -c -f "$TMP_SUDOERS" >/dev/null; then
  if [[ -f "$SUDOERS_FILE" ]] && cmp -s "$TMP_SUDOERS" "$SUDOERS_FILE"; then
    log "sudoers $SUDOERS_FILE : inchangé"
  else
    install -m 0440 -o root -g root "$TMP_SUDOERS" "$SUDOERS_FILE"
    log "sudoers $SUDOERS_FILE : mis à jour (0440 root:root)"
  fi
else
  rm -f "$TMP_SUDOERS"
  echo "ERREUR : sudoers généré invalide, abandon." >&2
  exit 1
fi
rm -f "$TMP_SUDOERS"

# ── 3. Clé SSH dédiée (optionnelle) avec restrictions ─────────────────────────
if [[ -n "$SSH_KEY" ]]; then
  SSH_DIR="$ATLAS_HOME/.ssh"
  AUTH="$SSH_DIR/authorized_keys"
  install -d -m 0700 -o "$ATLAS_USER" -g "$ATLAS_USER" "$SSH_DIR"
  # Restrictions : pas de port-forward, pty, X11, agent — clé d'exécution only.
  # Le command= forcé (vers le dispatcher du catalogue) sera ajouté en RM1816.
  RESTRICT="restrict"
  LINE="$RESTRICT $SSH_KEY"
  if [[ -f "$AUTH" ]] && grep -qF "$SSH_KEY" "$AUTH"; then
    log "ssh authorized_keys : clé déjà présente"
  else
    printf '%s\n' "$LINE" >> "$AUTH"
    chown "$ATLAS_USER:$ATLAS_USER" "$AUTH"
    chmod 0600 "$AUTH"
    log "ssh authorized_keys : clé ajoutée (restrict)"
  fi
fi

echo "✓ Provisioning atlas terminé sur $(hostname)."
