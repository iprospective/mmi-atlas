#!/usr/bin/env bash
# atlas-safe op (RM2050) — topologie MariaDB/MySQL. Read-only, bundle FIGÉ (0 arg).
# Privilégié (root) → NOPASSWD ciblé. Ne fait QUE lire : unités, sockets, ss, ps,
# tailles des datadirs, et `SHOW DATABASES` (lecture) sur chaque socket trouvé.
set -uo pipefail   # pas de -e : un sous-diagnostic qui échoue ne doit pas tout couper

sec() { printf '\n=== %s ===\n' "$1"; }

sec "unités systemd maria/mysql"
systemctl list-units --all --type=service --no-pager 2>/dev/null | grep -iE 'maria|mysql' || echo "(aucune)"

sec "mécanisme de lancement"
grep -rilE 'mysqld_multi|defaults-group-suffix|mysqld_safe' /etc/systemd /etc/init.d 2>/dev/null | head -5 || true
systemctl list-unit-files --no-pager 2>/dev/null | grep -iE 'maria|mysql' || true

sec "sockets /run/mysqld"
ls -la /run/mysqld/ 2>/dev/null || echo "(pas de /run/mysqld)"

sec "sockets/ports en écoute"
ss -lnpx 2>/dev/null | grep -i mysql || echo "(aucun socket unix mysql)"
ss -lntp 2>/dev/null | grep -iE 'mysqld|mariadbd' || true

sec "processus mariadbd/mysqld_safe"
ps -eo pid,user,cmd 2>/dev/null | grep -iE 'mysqld_safe|mariadbd' | grep -v grep || echo "(aucun process)"

sec "tailles des datadirs"
du -sh /var/lib/mysql /var/lib/mysql_* 2>/dev/null || echo "(aucun datadir)"

sec "SHOW DATABASES par socket"
mysql_bin="$(command -v mariadb || command -v mysql || true)"
if [ -z "$mysql_bin" ]; then
  echo "(client mariadb/mysql absent)"
else
  shopt -s nullglob
  for s in /run/mysqld/*.sock; do
    printf -- '-- %s\n' "$s"
    "$mysql_bin" --socket="$s" --connect-timeout=3 -N -e 'SHOW DATABASES' 2>&1 | grep -vE '^(information_schema|performance_schema|sys|mysql)$' | paste -sd' ' || true
  done
fi
