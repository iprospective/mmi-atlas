# Atlas — bot Telegram sysadmin sécurisé

Télécommande Telegram pour des opérations sysadmin privilégiées, avec sécurité
forte (whitelist + verrou applicatif TTL). Voir RM1812 (épic) et ses sous-tickets.

## État

- **RM1814 — squelette bot** (`atlas-bot.py`) : long-polling, whitelist, verrou
  PBKDF2 TTL, anti-brute-force, fail-secure. **Sans exécution privilégiée** —
  point d'extension `dispatch_operation()` prêt pour le catalogue.
- **RM1816 — catalogue de scripts vetted** : registre + validation d'args +
  exécution via user `atlas` + sudo ciblé + journal d'audit *(à venir)*.
- **RM1815 — provisioning** du user `atlas` + sudoers + clé SSH sur le parc, via
  `provision-atlas.sh` (script idempotent ; l'outil de config management —
  Puppet/Ansible/alt. — est arbitré dans RM1118).

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
