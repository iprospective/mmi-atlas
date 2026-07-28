# Atlas — agent IA sysadmin

**Atlas** est l'**agent compétent** de l'infrastructure iProspective : il détient le
plan d'accès aux hôtes (SSH, clés, policy, dispatch sécurisé, redaction, audit-trail)
**et** le tooling d'analyse (observe / corrèle / diagnostique / agit). C'est le seul
composant autorisé à se connecter aux machines et à y exécuter des opérations.

Extrait du monorepo `iprospective/sysadmin/infrastructure` (RM2421) pour lui donner sa
propre frontière de sécurité, son cycle de release et en faire un **service réutilisable**
piloté par des orchestrateurs (outil d'audit `iprospective/security`, orchestrateur PM).

## Frontière (décision d'archi RM2421)

Découpage en 3 rôles, graphe **acyclique** — *savoir → agent compétent → organisateur* :

- **`iprospective/sysadmin/infrastructure` = le SAVOIR** (ne dépend de personne) :
  déclaratif (`inventory/`, source de vérité des nœuds) + définitions d'observation
  (`scripts/discovery/` = code + *contrat* des sondes). Ne se connecte **jamais** à un
  hôte, ne fait **aucune** analyse. Il y a **N infra clientes** (`client-b/infra`,
  `client-a/infra`, … et `iprospective` = un client comme un autre), chacune détient
  *son* inventaire.
- **`iprospective/sysadmin/atlas` = l'AGENT COMPÉTENT** (ce repo, dépend d'infra) :
  accès hôte + tooling d'analyse. **Exécute** les sondes (elles sont des opérations
  « observe » de son catalogue, pas un canal d'accès concurrent dans infra).
  Multi-tenant ; son `nodes.json` est un artefact **dérivé** des inventaires clients.
- **`iprospective/security` (audits) = l'ORGANISATEUR** (dépend des deux) : référentiels,
  campagnes, RBAC, restitution ; **pilote atlas** comme un collaborateur, ne touche
  **jamais** un hôte. Détient les accès *organisationnels* (périmètre d'audit), pas les
  clés des serveurs.

Deux sens de « accès » : *accès hôte* (SSH/clés) → **atlas uniquement** ; *accès
organisationnel* (droit d'auditer un périmètre) → **audit**.

### Interfaces consommées depuis infra (contrats)
| Interface infra | Nature | Usage atlas |
|---|---|---|
| `inventory/` | déclaratif, source de vérité nœuds | dérive `nodes.json` |
| `scripts/discovery/` (sondes) | contrat de sortie versionné | atlas les **exécute** |
| Zabbix (`zabbix-host` + endpoint) | flux événements/contexte | ingest + `zabbix_api.py` |

## Composants

- **`atlas/`** — le cœur et ses interfaces :
  - `atlas-core.py` (+`.service`) : cœur (catalogue + moteur de décision + dispatch),
    socket local, journal d'accès unifié.
  - `catalogue.py` / `operations.py` / `ops/` : registre d'opérations vetted (validation
    stricte des args, exécution argv, audit JSONL).
  - `decision.py` / `policy.py` / `access.py` / `redact.py` : paliers d'autonomie, droits,
    redaction des secrets.
  - `atlas-cli.py`, `atlas-www.py` (+`.service`), `atlas-bot.py` (+`.service`) : opérateur
    central + runner, UI web, bot Telegram.
  - `atlas_client.py` / `atlas-client-runner.py` / `package-atlas-client.sh` /
    `client_dispatch.py` : dispatch d'action distant (cœur → `atlas-client` sur les nœuds).
  - `atlas-ingest.py` (+`.service`) / `zabbix_api.py` / `zabbix-webhook.js` : ingestion
    d'événements (Zabbix aujourd'hui ; `source="audit"` demain — pilotage par l'audit).
  - `atlas_ai.py` / `atlas-diagnose.py` : diagnosticien IA (aidiag).
  - `provision-atlas.sh`, `gen-sudoers.py`, `deploy-*.sh`, `atlas-ssh-agent.service`,
    `load-keys.sh` : provisioning user/sudoers/clés + déploiement vers `/opt/atlas`.
- **`atlas-safe/`** — dispatch durci en lecture seule sur la flotte (`atlas-safe-runner.py`,
  `operations_safe.py`, `ops/`) : substrat sûr pour le diagnosticien.

Configs runtime : voir les `*.env.example`, `rights.json.example`, `nodes.json.example`.

## Déploiement

L'agent tourne dans un conteneur LXC dédié ; le code est déployé dans `/opt/atlas`
(root-owned) via les `deploy-*.sh` (tar → `lxc-attach`). Le runtime est **découplé** du
repo : déplacer les sources ne perturbe pas l'agent vivant tant qu'on ne redéploie pas.

## Provenance

Historique git préservé (`git filter-repo` sur `scripts/atlas` + `scripts/atlas-safe`,
remontés à la racine) — RM2421, 2026-07-28. Série de tickets d'origine : RM1812-1818,
1848, 2039-2042, 2050, 2058, 2071-2072, 2079, 2092-2094 (migrés vers le projet PM atlas).
