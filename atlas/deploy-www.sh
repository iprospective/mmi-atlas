#!/usr/bin/env bash
# deploy-www.sh — déploie l'INTERFACE WEB Atlas dans son conteneur (RM2040).
#
# Sœur de deploy-bot.sh. Installe l'UI web sous le user dédié non privilégié
# `atlas-www` : code (root-owned, RO) + unit systemd + membership `atlas-ifaces`
# (accès socket du cœur) + cert TLS auto-signé in-container. ZÉRO sudoers (relais
# pur, comme le bot) : la console ne fait que soumettre une intention au cœur.
#
# Propriété (sécurité) : le code appartient à root, lecture seule pour `atlas-www` ;
# `www.env` (hash mdp) est root:atlas-www 0640 ; la clé TLS root:atlas-www 0640.
#
#   ./deploy-www.sh --container atlas [--primary node5]
#
# Idempotent / re-jouable. NE démarre PAS le service au 1er passage (hash mdp à
# remplir dans www.env d'abord).
set -euo pipefail

CONTAINER="" PRIMARY="" WWW_USER="atlas-www" NODES="node3 node4 node5"
HERE="$(cd "$(dirname "$0")" && pwd)"
# atlas-www s'appuie sur le client socket + le catalogue (listing) — mêmes modules
# que le cœur/bot ; on les pousse pour que l'UI soit autoportante si déployée seule.
CODE=(atlas-www.py atlas_client.py catalogue.py operations.py)

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while [[ $# -gt 0 ]]; do case "$1" in
  --container) CONTAINER="$2"; shift 2 ;;
  --primary)   PRIMARY="$2"; shift 2 ;;
  --user)      WWW_USER="$2"; shift 2 ;;
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
echo "▸ Déploiement web Atlas dans ${CONTAINER} (hôte ${PRIMARY}, user ${WWW_USER})"

# 1) Code → /opt/atlas (root-owned, RO). On n'écrase PAS les modules déjà posés par
#    le cœur s'ils sont identiques (tar idempotent) ; ici on (re)pousse les nôtres.
echo "▸ Code → /opt/atlas (root:root, RO)"
ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- install -d -m 0755 -o root -g root /opt/atlas"
umask 022
tar -C "$HERE" -czf - "${CODE[@]}" | ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- tar xzf - -C /opt/atlas"

# 2) Unit + 3) www.env (template si absent)
cat "$HERE/atlas-www.service" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/etc/systemd/system/atlas-www.service >/dev/null"
ssh "$PRIMARY" "sudo test -f /zfs/lxc/${CONTAINER}/opt/atlas/www.env" \
  || cat "$HERE/www.env.example" | ssh "$PRIMARY" "sudo tee /zfs/lxc/${CONTAINER}/opt/atlas/www.env >/dev/null"

echo "▸ User ${WWW_USER}, cert TLS, ownership, enable (dans ${CONTAINER})"
WWW_USER="$WWW_USER" CONTAINER="$CONTAINER" ssh "$PRIMARY" "sudo lxc-attach -n ${CONTAINER} -- env WWW_USER=$WWW_USER CONTAINER=$CONTAINER bash -s" <<'SH'
set -e
U="${WWW_USER:-atlas-www}"
getent group atlas-ifaces >/dev/null || groupadd --system atlas-ifaces
id "$U" >/dev/null 2>&1 || useradd --system --home-dir /opt/atlas --no-create-home --shell /usr/sbin/nologin "$U"
usermod -aG atlas-ifaces "$U"
cd /opt/atlas
# code → root (RO pour l'UI) ; www.env → root:U 0640
chown root:root atlas-www.py atlas_client.py catalogue.py operations.py
chmod 0644 atlas-www.py atlas_client.py catalogue.py operations.py
[ -f /opt/atlas/www.env ] && chown root:"$U" /opt/atlas/www.env && chmod 0640 /opt/atlas/www.env || true
rm -rf __pycache__ 2>/dev/null || true
# Cert TLS auto-signé in-container (RM2040), généré une seule fois. Clé lisible par U.
install -d -m 0750 -o root -g "$U" /opt/atlas/tls
if [ ! -f /opt/atlas/tls/www.key ]; then
  CN="${CONTAINER:-atlas}.example.net"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout /opt/atlas/tls/www.key -out /opt/atlas/tls/www.crt \
    -subj "/CN=${CN}/O=iProspective/OU=Atlas" \
    -addext "subjectAltName=DNS:${CN},DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
  echo "  ✓ cert TLS auto-signé généré (CN=${CN})"
fi
chown root:"$U" /opt/atlas/tls/www.key /opt/atlas/tls/www.crt
chmod 0640 /opt/atlas/tls/www.key; chmod 0644 /opt/atlas/tls/www.crt
# Zéro privilège : aucun sudoers pour l'UI (idempotent).
rm -f /etc/sudoers.d/atlas-www
systemctl daemon-reload
if systemctl is-active --quiet atlas-www; then systemctl restart atlas-www; else systemctl enable atlas-www.service >/dev/null 2>&1 || true; fi
echo "  ✓ sudo $U (doit être 0) : $(sudo -l -U "$U" 2>/dev/null | grep -c NOPASSWD)"
echo "  ✓ www: $(systemctl is-active atlas-www 2>/dev/null || echo inactif)"
SH

echo "✓ Interface web déployée dans ${CONTAINER}."
echo "  Reste à la main : remplir /opt/atlas/www.env (ATLAS_WWW_PASSWORD_HASH via"
echo "  'python3 /opt/atlas/atlas-www.py --hash-password'), puis 'systemctl start atlas-www'."
