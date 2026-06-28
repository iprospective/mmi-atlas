#!/usr/bin/env python3
"""operations_safe — registre des ops READ-ONLY d'atlas-safe (RM2050).

`atlas-safe` est l'agent **lecture seule** déployé sur chaque nœud : il n'a
**aucun droit par défaut**. Chaque capacité de diagnostic est un **grain explicite**
— une op vettée, args validés en argv par `catalogue.py`, et (si root nécessaire)
**une seule ligne NOPASSWD** générée depuis ce registre. On en ajoute au compte-goutte.

Invariant : **tout est read-only**. Aucune op ne modifie l'état. Aucun chemin ni
flag libre n'est accepté (le NOPASSWD ne porte que sur le script vetté ; les args
sont des listes blanches / motifs bornés → pas de « sudo tail /etc/shadow »).

Le LLM (atlas-ai) ne fait que **raisonner** sur la sortie de ces ops ; il ne les
choisit pas (v1). Le cœur dispatche un bundle fixe par classe de trigger.
"""
import re

from catalogue import ArgSpec, Operation, OPS_DIR, RE_SERVICE

# Motif de recherche (grep) : borné, caractères sûrs uniquement. Passé en argv +
# en **chaîne fixe** (grep -F) côté script → ni injection shell, ni ReDoS.
RE_GREP = re.compile(r"^[\w .:@/=+-]{1,80}$")

# Logs nommés (liste blanche) — JAMAIS un chemin libre. Le mapping nom→chemin est
# figé dans tail-log.sh ; cette liste DOIT rester alignée dessus.
LOG_NAMES = ("syslog", "auth", "kern", "daemon", "dpkg")

OPERATIONS = (
    Operation(
        id="disk-usage",
        description="Utilisation disque (df -h)",
        script=OPS_DIR / "disk-usage.sh",
        args=(),
        autonomy="P0", target="host", reversible=True, needs_sudo=False,
    ),
    Operation(
        id="service-status",
        description="État d'un service systemd",
        script=OPS_DIR / "service-status.sh",
        args=(ArgSpec("service", "token", pattern=RE_SERVICE),),
        autonomy="P0", target="host", reversible=True, needs_sudo=False,
    ),
    Operation(
        id="journal",
        description="Dernières lignes du journal d'une unité (journalctl -u)",
        script=OPS_DIR / "journal.sh",
        args=(ArgSpec("unit", "token", pattern=RE_SERVICE),
              ArgSpec("lines", "int", min=1, max=500, required=False)),
        autonomy="P0", target="host", reversible=True, needs_sudo=True,
    ),
    Operation(
        id="tail-log",
        description="Fin d'un log système nommé (+ filtre optionnel)",
        script=OPS_DIR / "tail-log.sh",
        args=(ArgSpec("log", "choice", choices=LOG_NAMES),
              ArgSpec("lines", "int", min=1, max=500, required=False),
              ArgSpec("pattern", "token", pattern=RE_GREP, required=False)),
        autonomy="P0", target="host", reversible=True, needs_sudo=True,
    ),
    Operation(
        id="db-instances",
        description="Topologie MariaDB/MySQL multi-instances (bundle figé)",
        script=OPS_DIR / "db-instances.sh",
        args=(),
        autonomy="P0", target="host", reversible=True, needs_sudo=True,
    ),
    Operation(
        id="sysload",
        description="Charge / mémoire / top process CPU+RAM (read-only, sans sudo)",
        script=OPS_DIR / "sysload.sh",
        args=(),
        autonomy="P0", target="host", reversible=True, needs_sudo=False,
    ),
)
