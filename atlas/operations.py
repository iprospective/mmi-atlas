#!/usr/bin/env python3
"""operations — registre déclaratif des opérations Atlas.

RM1816 pose le CADRE (ce fichier + catalogue.py) avec des opérations de référence
read-only. RM1817 ajoute les premières opérations PRIVILÉGIÉES (catalogue v1) :
restart de service, snapshot ZFS, restart de conteneur LXC, tail de logs.

Chaque opération privilégiée (`needs_sudo=True`) :
  - a un script vetted dans `ops/` ;
  - voit ses arguments validés par le catalogue AVANT exécution ;
  - nécessite une ligne sudoers ciblée (générée depuis ce registre par
    `gen-sudoers.py`, déployée par `deploy-atlas.sh`).

Paliers d'autonomie (cf. RM1813) :
  P0 lecture seule · P1 sûr/idempotent/réversible · P2 disruptif (approbation).
"""
from catalogue import (ArgSpec, Operation, OPS_DIR,
                       RE_SERVICE, RE_CONTAINER, RE_ZFS_DATASET, RE_LABEL)
from zabbix_ops import ZABBIX_OPERATIONS  # ops API Zabbix (RM2496) — target 'api'

OPERATIONS = (
    # ── Référence read-only (RM1816) ────────────────────────────────────────
    Operation(
        id="disk-usage",
        description="Utilisation disque (df -h)",
        script=OPS_DIR / "disk-usage.sh",
        args=(),
        autonomy="P0", target="host", reversible=True, needs_sudo=False,
    ),
    Operation(
        id="service-status",
        description="État d'un service systemd / pool FPM",
        script=OPS_DIR / "service-status.sh",
        args=(ArgSpec("service", "token", pattern=RE_SERVICE),),
        autonomy="P0", target="host", reversible=True, needs_sudo=False,
    ),

    # ── Catalogue v1 privilégié (RM1817) ────────────────────────────────────
    Operation(
        id="restart-service",
        description="Redémarre un service systemd / pool FPM",
        script=OPS_DIR / "restart-service.sh",
        args=(ArgSpec("service", "token", pattern=RE_SERVICE),),
        autonomy="P2",            # disruptif → approbation (RM1813)
        target="host", reversible=True, needs_sudo=True,
    ),
    Operation(
        id="zfs-snapshot",
        description="Crée un snapshot ZFS d'un dataset (point de rollback)",
        script=OPS_DIR / "zfs-snapshot.sh",
        args=(ArgSpec("dataset", "token", pattern=RE_ZFS_DATASET),
              ArgSpec("label", "token", pattern=RE_LABEL, required=False)),
        autonomy="P1",            # additif, sûr, réversible
        target="host", reversible=True, needs_sudo=True,
    ),
    Operation(
        id="restart-lxc",
        description="Redémarre un conteneur LXC (via opensvc, instance locale)",
        script=OPS_DIR / "restart-lxc.sh",
        args=(ArgSpec("container", "token", pattern=RE_CONTAINER),),
        autonomy="P2",            # disruptif → approbation (RM1813)
        target="host", reversible=True, needs_sudo=True,
    ),
    Operation(
        id="tail-log",
        description="Affiche la fin d'un log système (liste blanche)",
        script=OPS_DIR / "tail-log.sh",
        args=(ArgSpec("log", "choice", choices=("syslog", "auth", "kern", "dpkg")),
              ArgSpec("lines", "int", min=1, max=500, required=False)),
        autonomy="P0",            # lecture seule
        target="host", reversible=True, needs_sudo=True,
    ),
) + ZABBIX_OPERATIONS
