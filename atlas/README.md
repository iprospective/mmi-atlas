# Atlas — bot Telegram sysadmin sécurisé

Télécommande Telegram pour des opérations sysadmin privilégiées, avec sécurité
forte (whitelist + verrou applicatif TTL). Voir RM1812 (épic) et ses sous-tickets.

## État

- **RM1814 — squelette bot** (`atlas-bot.py`) : long-polling, whitelist, verrou
  PBKDF2 TTL, anti-brute-force, fail-secure. Branché sur le catalogue (`/ops`, `/run`).
- **RM1816 — catalogue de scripts vetted** (`catalogue.py` + `operations.py` +
  `ops/`) : registre déclaratif, validation stricte des arguments (liste
  blanche / motif / bornes, anti-injection), exécution en argv (jamais de shell),
  journal d'audit JSONL. Auto-tests : `python3 test_catalogue.py`.
- **RM1815 — provisioning** du user `atlas` + sudoers + clé SSH sur le parc, via
  `provision-atlas.sh` (script idempotent ; l'outil de config management —
  Puppet/Ansible/alt. — est arbitré dans RM1118).

## Catalogue d'opérations

Une opération = un script vetted dans `ops/` + une entrée déclarative dans
`operations.py` (id, description, schéma d'arguments, palier d'autonomie, cible,
réversibilité, `needs_sudo`). Le framework (`catalogue.py`) **valide chaque
argument avant exécution** et **n'interpole jamais** dans un shell.

```bash
python3 test_catalogue.py          # auto-tests (validation, anti-injection, audit)
```

Opérations de référence (read-only, palier P0) : `disk-usage`, `service-status`.
Les opérations privilégiées (restart FPM, snapshot ZFS, restart LXC, limite RAM…)
sont ajoutées par **RM1817**, une à une, chacune avec sa ligne sudoers ciblée.
Audit : `scripts/atlas/data/audit.jsonl` (gitignoré ; `$ATLAS_AUDIT_PATH` pour surcharger).

## Démarrer le bot (dev)

```bash
cp .env.example .env            # puis renseigner le token + whitelist
python3 atlas-bot.py --hash-password   # génère ATLAS_LOCK_PASSWORD_HASH → .env
python3 atlas-bot.py
```

## Sécurité

- **Facteur 1** : whitelist d'IDs Telegram (`ATLAS_WHITELIST`).
- **Facteur 2** : verrou applicatif. Empreinte PBKDF2 (mdp jamais en clair),
  `/unlock` effacé de l'historique, auto-lock court (défaut 120 s vu le sudo),
  lockout après 3 échecs, état en mémoire → **fail-secure** au redémarrage.
- Le bot n'exécute **jamais** de commande arbitraire : seulement les opérations
  du catalogue vetted (RM1816), via le user `atlas` aux droits sudo ciblés.
