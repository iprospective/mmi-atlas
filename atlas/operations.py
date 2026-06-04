#!/usr/bin/env python3
"""operations — registre déclaratif des opérations Atlas.

RM1816 pose le CADRE (ce fichier + catalogue.py) avec quelques opérations de
référence read-only. Le CONTENU privilégié (restart FPM, snapshot ZFS, restart
LXC, limite RAM…) est ajouté par RM1817, une opération à la fois, chacune
reviewée : un script vetted dans `ops/`, une entrée ici, et — si `needs_sudo` —
une ligne sudoers ciblée déployée par provision-atlas.sh.
"""
from catalogue import ArgSpec, Operation, OPS_DIR, RE_SERVICE

OPERATIONS = (
    Operation(
        id="disk-usage",
        description="Utilisation disque (df -h)",
        script=OPS_DIR / "disk-usage.sh",
        args=(),
        autonomy="P0",          # lecture seule → sûr
        target="host",
        reversible=True,
        needs_sudo=False,
    ),
    Operation(
        id="service-status",
        description="État d'un service systemd / pool FPM",
        script=OPS_DIR / "service-status.sh",
        args=(ArgSpec("service", "token", pattern=RE_SERVICE),),
        autonomy="P0",          # lecture seule → sûr
        target="host",
        reversible=True,
        needs_sudo=False,
    ),
)
