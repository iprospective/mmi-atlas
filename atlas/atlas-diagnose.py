#!/usr/bin/env python3
"""atlas-diagnose — démo bout-en-bout du diagnosticien (RM2050).

Collecte read-only on-target (via atlas-safe) + raisonnement LLM (atlas-ai) :

    atlas-diagnose.py <nœud> [profil]      # profil ∈ {base, db} (défaut base)

À lancer sur le conteneur `atlas` (clé atlas-safe + accès ai.lan requis). Sert de
préfiguration du chemin qui sera câblé dans le cœur (event → dispatch → IA → Telegram).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from safe_dispatch import diagnose_bundle           # noqa: E402
from atlas_ai import diagnose, AIUnavailable          # noqa: E402
from policy import DIAG_PROFILES as PROFILES          # noqa: E402


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: atlas-diagnose.py <nœud> [base|db]")
    node = sys.argv[1]
    profile = sys.argv[2] if len(sys.argv) > 2 else "base"
    ops = PROFILES.get(profile)
    if ops is None:
        sys.exit(f"profil inconnu : {profile} (dispo: {', '.join(PROFILES)})")

    event = {"source": "manual-demo", "host": node, "trigger": f"diagnostic {profile}",
             "severity": "high", "state": "PROBLEM"}

    print(f"▸ Collecte read-only on-target ({node}, profil {profile})…", file=sys.stderr)
    diags = diagnose_bundle(node, ops)
    for d in diags:
        mark = "✓" if d.get("ok") else "✗"
        print(f"  {mark} {d.get('op')} {' '.join(d.get('args', []))}", file=sys.stderr)

    print("▸ Raisonnement LLM (atlas-ai)…", file=sys.stderr)
    try:
        text = diagnose(event, diags)
    except AIUnavailable as e:
        sys.exit(f"IA indisponible : {e}")

    print("\n===== DIAGNOSTIC ATLAS =====\n")
    print(text)
    print("\n============================")


if __name__ == "__main__":
    main()
