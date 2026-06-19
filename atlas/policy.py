#!/usr/bin/env python3
"""policy — politique d'autonomie par défaut d'Atlas (RM1813).

Mapping **trigger Zabbix → palier** consommé par le moteur (`decision.py`). La
politique vit **côté Atlas** (pas dans Zabbix) : un seul endroit reviewable,
versionné, auditable. Posture par défaut : **deny-to-notify** — tout ce qui ne
matche aucune règle reste en **P0 (notify only)**.

Chaque règle P1/P2 référence une **op du catalogue** (`operations.py`) — donc déjà
validée en argv, allowlistée et sudo-restreinte. Les `{host}` / `{item}` sont
substitués depuis l'événement (valeurs elles-mêmes re-validées par le catalogue).

⚠ Règle d'or (cf. ticket) : seules des opérations **idempotentes et réversibles**
en P1. Tout ce qui est destructif/irréversible → **P2 minimum** (approbation).
"""
from decision import Rule

# Diagnostic par défaut joint à TOUTE alerte (PROBLEM) — ops **read-only** (P0)
# uniquement ; le cœur refuse d'exécuter en diagnostic une op non read-only.
# C'est le « par défaut, Atlas peut poser un diagnostic » : lancé même en plafond
# `observe`, où aucune remédiation n'a lieu.
DEFAULT_DIAGNOSE = (
    ("disk-usage", ()),               # pression disque, toujours pertinent et sûr
)

# Ordre = priorité : la première règle qui matche gagne.
POLICY = [
    # ── P1 — auto-remédiation allowlistée (idempotent / réversible) ──────────
    # Pool PHP-FPM tombé : un restart est idempotent et réversible. L'item Zabbix
    # porte le nom du pool/unité → {item}, re-validé par le catalogue (RE_SERVICE).
    Rule("fpm-pool-down",
         trigger=r"(?i)\bFPM\b.*\b(down|crash|unavailable)\b|pool .* (down|inactive)",
         tier="P1", op="restart-service", args=("{item}",),
         min_severity="average", max_per_hour=3, cooldown_s=300,
         diagnose=(("service-status", ("{item}",)),)),   # état du pool avant tout

    # ── P2 — approbation humaine inline (impact plus large) ──────────────────
    # Redémarrer un conteneur LXC coupe tous ses services → jamais en auto.
    Rule("lxc-container-down",
         trigger=r"(?i)\b(container|lxc)\b.*\b(down|unreachable|stopped)\b",
         tier="P2", op="restart-lxc", args=("{host}",),
         min_severity="high", max_per_hour=2, cooldown_s=600),

    # ── never — explicitement « jamais d'action automatique » ────────────────
    # Signaux qui exigent un humain (matériel, redémarrage hôte, corruption…).
    Rule("needs-human",
         trigger=r"(?i)\b(reboot|hardware|raid|smart|corrupt|kernel panic)\b",
         tier="never"),

    # ── P0 — notify only (filet large : disque, charge, services divers) ─────
    Rule("disk-pressure", trigger=r"(?i)\b(disk|filesystem|inode)\b", tier="P0"),
    Rule("load-pressure", trigger=r"(?i)\b(load|cpu|memory|swap)\b", tier="P0"),
    # Tout le reste retombe sur le défaut deny-to-notify du moteur (P0).
]
