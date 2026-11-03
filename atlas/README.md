# Atlas — agent de déploiement et d’administration limitée

Atlas est le composant de l’écosystème iProspective chargé des **déploiements**
et des **opérations d’administration** sur les serveurs. Il ne dispose pas d’un
accès root général : il agit via un utilisateur dédié, un catalogue d’opérations
vetted et des droits sudoers ciblés.

Le bot Telegram reste une interface parmi d’autres ; le cœur Atlas expose aussi
un canal orchestrateur utilisé par Karl/PM pour les snapshots pré-MEP.

## Rôle

- exécuter des déploiements et des opérations d’exploitation ;
- fournir un point d’entrée contrôlé vers les serveurs ;
- conserver un journal d’audit des actions ;
- exposer aux outils de l’écosystème (Karl/PM, supervision) des opérations
  limitées et réversibles.

## Modèle de sécurité

- **Utilisateur système dédié** : `atlas`, sans shell interactif général.
- **Sudoers généré depuis le registre** : une ligne par script autorisé, jamais
  une règle globale.
- **Catalogue fermé** : aucune commande arbitraire ; les arguments sont validés
  avant exécution et jamais interpolés dans un shell.
- **Moindre privilège** : les opérations sont classées P0/P1/P2 ; les plus
  sensibles exigent une confirmation ou un canal spécifique.
- **Audit** : journal JSONL des actions, des acteurs et des résultats.
- **Pas de secrets dans le dépôt** : les tokens, clés SSH et mots de passe sont
  fournis par l’environnement ou Vaultwarden.

## Composants

| Composant | Rôle |
|---|---|
| `atlas-core.py` | cœur d’exécution, catalogue et politique |
| `atlas-bot.py` | interface Telegram, whitelist et verrou TTL |
| `atlas-ingest.py` | ingestion d’événements de supervision |
| `atlas-www.py` | interface web read-only/relais |
| `atlas-cli.py` | CLI opérateur |
| `atlas_client.py`, `atlas-client-runner.py` | exécution côté cible |
| `orch_runner.py`, `orch-client.sh` | canal orchestrateur pour Karl/PM |
| `catalogue.py`, `operations.py`, `ops/` | registre et scripts vetted |

## Catalogue d’opérations

Une opération = un script vetted dans `ops/` + une entrée déclarative dans
`operations.py` : identifiant, description, schéma d’arguments, palier
d’autonomie, cible, réversibilité et `needs_sudo`.

```bash
python3 test_catalogue.py          # validation, anti-injection, audit
```

| id | palier | sudo | description |
|----|--------|------|-------------|
| `disk-usage` | P0 | non | espace disque |
| `service-status` | P0 | non | état d’un service systemd |
| `tail-log` | P0 | oui | fin d’un log système, liste blanche |
| `zfs-snapshot` | P1 | oui | snapshot ZFS d’un dataset |
| `restart-service` | P2 | oui | redémarrage d’un service ou pool FPM |
| `restart-lxc` | P2 | oui | redémarrage d’un conteneur LXC via OpenSVC |
| `svc-status` | P0 | oui | état d’une instance OpenSVC |
| `svc-snapshot` | P1 | oui | point de restauration pré-MEP via OpenSVC |

`svc-status` et `svc-snapshot` sont aussi accessibles au canal orchestrateur
(`orch_runner.py`, clé dédiée) avec `--node <nœud>`. C’est le mécanisme utilisé
par Karl/PM pour prendre un snapshot pré-MEP sans accès hôte côté PM.

## Déploiement

```bash
python3 gen-sudoers.py                  # génère le sudoers depuis operations.py
./deploy-atlas.sh <node>                # ops + sudoers sur un hôte
./deploy-atlas.sh <node> --lxc <name>   # ops + sudoers dans un conteneur
```

Les scripts de déploiement sont idempotents et vérifient le sudoers avec
`visudo -c`. Les noms de nœuds et les chemins de clés sont fournis par la
configuration locale, jamais codés en dur dans le dépôt public.

## Configuration

Copier les fichiers d’exemple et renseigner les valeurs hors dépôt :

```bash
cp .env.example .env
cp nodes.json.example nodes.json
cp rights.json.example rights.json
```

Les fichiers `.env`, `nodes.json`, `rights.json` et les journaux d’audit ne
doivent jamais être versionnés.

## Tests

```bash
python3 test_catalogue.py
python3 test_access.py
python3 test_dispatch.py
python3 test_orch_runner.py
python3 test_zabbix.py
```

## Intégration écosystème

- **Karl/PM** : pilotage des tâches et des environnements ; utilise le canal
  orchestrateur pour les snapshots et certaines opérations.
- **Supervision** : ingestion d’événements et opérations Zabbix contrôlées.
- **Vaultwarden** : secrets et identifiants hors dépôt.
- **GitLab/GitHub** : code source ; les détails d’exploitation restent dans les
  documents privés.

## Licence

GPL-3.0-or-later — voir `LICENSE`.
