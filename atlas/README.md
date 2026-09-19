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

**Opérations disponibles**

| id | palier | sudo | description |
|----|--------|------|-------------|
| `disk-usage` | P0 | non | `df -h` (réf. RM1816) |
| `service-status` | P0 | non | état d'un service systemd (réf. RM1816) |
| `tail-log` | P0 | oui | fin d'un log système (liste blanche) |
| `zfs-snapshot` | P1 | oui | snapshot ZFS d'un dataset (rollback) |
| `restart-service` | P2 | oui | redémarre un service / pool FPM |
| `restart-lxc` | P2 | oui | redémarre un conteneur LXC (via opensvc) |
| `svc-status` | P0 | oui | état de l'instance locale d'un service opensvc (up/down/absent) — RM3254 |
| `svc-snapshot` | P1 | oui | point de restauration pré-MEP : `om <svc> sync update --rid sync#root_*`, instance `up` exigée, rend le nom du snapshot — RM3254 |

`svc-status` et `svc-snapshot` sont aussi ouvertes au **canal orchestrateur**
(`orch_runner.py`, clé `atlas-orch`) avec `--node <nœud>` : c'est ainsi que l'outil PM
`pm-snapshot` (RM2989) prend le snapshot pré-MEP sans aucun accès hôte côté PM (D3, RM2421).

Les opérations privilégiées (`needs_sudo`) tournent via le user `atlas` avec une
ligne sudoers **ciblée par script**, **générée depuis le registre** (jamais à la
main) :

```bash
python3 gen-sudoers.py            # → /etc/sudoers.d/atlas (depuis operations.py)
./deploy-atlas.sh <ssh-node>      # déploie ops/ → /opt/atlas/ops + installe le sudoers (visudo -c)
```

Sur un nœud déployé, pointer le catalogue vers les scripts installés via
`ATLAS_OPS_DIR=/opt/atlas/ops`. Audit : `scripts/atlas/data/audit.jsonl`
(gitignoré ; `$ATLAS_AUDIT_PATH` pour surcharger).

> À venir : `set-lxc-ram` (lié à la limite RAM RM1797, mécanisme cgroup/lxcfs à
> stabiliser) ; exécution **distante** des ops via dispatcher SSH (RM1813).

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
