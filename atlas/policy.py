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

# Diagnostic par défaut joint à TOUTE alerte (PROBLEM).
#
# ⚠ VIDE pour l'instant : un diagnostic doit tourner **sur le nœud concerné** par
# l'événement (ex. `df`/`systemctl status` sur `calicote`), PAS en local sur le
# conteneur `atlas` (sans intérêt pour un problème distant). L'exécution read-only
# **on-target** (via `atlas-safe` + dispatch SSH read-only) est le job de **RM2050** ;
# le framework de diagnostic (decision.py `diagnose` + cœur `_run_diagnostics`, gardé
# P0 read-only) reste en place, dormant, et sera peuplé là-bas avec `node = event.host`.
DEFAULT_DIAGNOSE = ()

# Profils de diagnostic ON-TARGET (RM2050) : bundles d'ops read-only `atlas-safe`
# dispatchés par le cœur SUR le nœud concerné (event.host), puis raisonnés par atlas-ai.
# (op_id, [args]) — ops du catalogue atlas-safe (operations_safe.py).
DIAG_PROFILES = {
    "base": [("disk-usage", []), ("tail-log", ["syslog", "40"])],
    "load": [("sysload", []), ("tail-log", ["syslog", "30"])],
    "disk": [("disk-usage", []), ("tail-log", ["syslog", "30"])],
    "db":   [("db-instances", []), ("service-status", ["mariadb"]),
             ("journal", ["mariadb", "40"])],
}

# Ordre = priorité : la première règle qui matche gagne.
POLICY = [
    # ── P1 — auto-remédiation allowlistée (idempotent / réversible) ──────────
    # Pool PHP-FPM tombé : un restart est idempotent et réversible. L'item Zabbix
    # porte le nom du pool/unité → {item}, re-validé par le catalogue (RE_SERVICE).
    Rule("fpm-pool-down",
         trigger=r"(?i)\bFPM\b.*\b(down|crash|unavailable)\b|pool .* (down|inactive)",
         tier="P1", op="restart-service", args=("{item}",),
         min_severity="average", max_per_hour=3, cooldown_s=300,
         diag_profile="base"),

    # ── P2 — approbation humaine inline (impact plus large) ──────────────────
    # Redémarrer un conteneur LXC coupe tous ses services → jamais en auto.
    Rule("lxc-container-down",
         trigger=r"(?i)\b(container|lxc)\b.*\b(down|unreachable|stopped)\b",
         tier="P2", op="restart-lxc", args=("{host}",),
         min_severity="high", max_per_hour=2, cooldown_s=600),

    # ── P0 + diagnostic IA on-target (RM2050) ────────────────────────────────
    # Un service DB down : on NE redémarre PAS en auto (disruptif) → notify, mais on
    # déclenche le diagnostic read-only on-target (atlas-safe) + le raisonnement atlas-ai.
    Rule("db-down",
         trigger=r"(?i)\b(mysql|mariadb|database)\b.*\b(down|service|unavailable|crash|stopp?ed)\b"
                 r"|\bservice is down\b.*\b(mysql|mariadb)\b",
         tier="P0", min_severity="average", diag_profile="db"),

    # ── never — explicitement « jamais d'action automatique » ────────────────
    # Signaux qui exigent un humain (matériel, redémarrage hôte, corruption…).
    Rule("needs-human",
         trigger=r"(?i)\b(reboot|hardware|raid|smart|corrupt|kernel panic)\b",
         tier="never"),

    # ── P0 — notify only (filet large : disque, charge, services divers) ─────
    Rule("disk-pressure", trigger=r"(?i)\b(disk|filesystem|inode)\b", tier="P0",
         diag_profile="disk"),
    Rule("load-pressure", trigger=r"(?i)\b(load|cpu|memory|swap)\b", tier="P0",
         diag_profile="load"),
    # Tout le reste retombe sur le défaut deny-to-notify du moteur (P0).
]
