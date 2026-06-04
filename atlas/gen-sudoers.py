#!/usr/bin/env python3
"""gen-sudoers — génère le sudoers d'Atlas depuis le registre (RM1817).

Émet une ligne NOPASSWD ciblée par opération PRIVILÉGIÉE (needs_sudo=True),
pointant vers le script déployé dans /opt/atlas/ops/. Source de vérité unique =
operations.py : on ne maintient JAMAIS le sudoers à la main.

Les arguments sont validés côté catalogue (liste blanche / motif / bornes) ; sudo
n'autorise que le chemin du script. Sortie sur stdout (installée par
deploy-atlas.sh, après `visudo -c`).

    python3 gen-sudoers.py            # → /etc/sudoers.d/atlas
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from operations import OPERATIONS

PROD_OPS_DIR = os.environ.get("ATLAS_PROD_OPS_DIR", "/opt/atlas/ops")
USER = os.environ.get("ATLAS_USER", "atlas")


def render():
    lines = [
        "# /etc/sudoers.d/atlas — généré par gen-sudoers.py depuis operations.py.",
        "# NE PAS éditer à la main. Une ligne = une opération privilégiée du catalogue.",
        "# Les arguments sont validés côté catalogue (pas par sudo).",
    ]
    priv = sorted((op for op in OPERATIONS if op.needs_sudo), key=lambda o: o.id)
    if not priv:
        lines.append("# (aucune opération privilégiée)")
    for op in priv:
        lines.append(f"{USER} ALL=(root) NOPASSWD: {PROD_OPS_DIR}/{op.script.name}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.stdout.write(render())
