#!/usr/bin/env python3
"""access — substrat PARTAGÉ des interfaces Atlas : journal d'accès + droits (RM2079).

`atlas-bot`, `atlas-www`, `atlas-cli` (et `atlas-ingest`) sont **3+1 surfaces d'accès**
au même cœur. Ce module réalise le principe « une seule autorité » (docs/atlas-architecture.md)
en concentrant AU CŒUR ce qui doit être partagé :

  1. **Journal d'accès / sessions unifié** (`AccessLog`) — UNE ligne JSONL par requête
     socket, **toute interface, tout `kind`** : qui (peer-cred → interface) + acteur
     end-user + quoi (kind/op/node, args **rédigés**) + **décision d'autorisation** +
     résultat. Sessions ET actions au même endroit (`data/access.jsonl`).
  2. **Droits partagés** (`Rights`) — autorisation consultée AVANT exécution, quel que
     soit le canal, **par interface ET par acteur** (RM2079, choix retenu). Défense en
     profondeur : même une interface compromise reste bornée par le cœur.

L'**authentification** reste à l'interface (whitelist+verrou du bot, Basic+TLS du www) ;
l'**autorisation** (qui a le droit de quoi) vit ici. L'identité d'interface est sûre
(SO_PEERCRED, socket 0660 groupe `atlas-ifaces`) ; l'`actor` est l'identité end-user que
l'interface cautionne (jamais une source de confiance en soi — mais une clé de droits/audit).
"""
import json
import os
import pwd
import threading
from datetime import datetime, timezone
from pathlib import Path

import redact

# Ordre des paliers d'autonomie (cf. catalogue.AUTONOMY_TIERS). "never" = plafond
# qui n'autorise AUCUNE op directe.
_TIER_RANK = {"P0": 0, "P1": 1, "P2": 2}


def _rank(tier):
    return _TIER_RANK.get(tier, 99)


# ── Droits par défaut (sûrs) ────────────────────────────────────────────────
# Surchargeables via un fichier JSON (ATLAS_RIGHTS_FILE) de même forme. Clés :
#   interfaces.<user> = {kinds:[...], op_max_tier: P0|P1|P2|never,
#                        allow_ops?:[...], deny_ops?:[...]}
#   default           = idem (interface inconnue)
#   actors.<actor>    = override explicite par end-user (tighten OU loosen)
#
# Posture : les interfaces interactives (bot/www/cli) portent l'humain-opérateur →
# peuvent lancer les ops du catalogue (plafond P2, comportement historique préservé).
# `atlas-ingest` est le chemin AUTONOME : il ne peut QUE soumettre des `event` (jamais
# d'op directe). Toute interface inconnue : lecture seule (status/poll).
DEFAULT_RIGHTS = {
    "interfaces": {
        "atlas-bot":    {"kinds": ["op", "diag", "aidiag", "status", "poll", "resolve"],
                         "op_max_tier": "P2"},
        "atlas-www":    {"kinds": ["op", "diag", "status", "poll"],
                         "op_max_tier": "P2"},
        "atlas-cli":    {"kinds": ["op", "diag", "aidiag", "status", "poll", "resolve"],
                         "op_max_tier": "P2"},
        "atlas-ingest": {"kinds": ["event", "status"],
                         "op_max_tier": "never"},
    },
    "default": {"kinds": ["status", "poll"], "op_max_tier": "never"},
    "actors": {},
}


def peer_user(uid):
    """Nom de l'utilisateur (= interface) derrière le socket, via le peer-cred uid."""
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, TypeError):
        return f"uid:{uid}"


class Rights:
    """Modèle d'autorisation partagé : check(interface, actor, kind, op, autonomy)."""

    def __init__(self, table=None, source="builtin"):
        self.table = table or DEFAULT_RIGHTS
        self.source = source

    @classmethod
    def load(cls):
        """Charge la table depuis ATLAS_RIGHTS_FILE (JSON) si présent, sinon défaut sûr."""
        path = os.environ.get("ATLAS_RIGHTS_FILE")
        if path and Path(path).is_file():
            try:
                table = json.loads(Path(path).read_text(encoding="utf-8"))
                return cls(table, source=f"file:{path}")
            except (ValueError, OSError):
                pass  # fichier illisible → on retombe sur le défaut sûr (fail-closed côté droits)
        return cls(DEFAULT_RIGHTS, source="builtin")

    def _policy_for(self, interface, actor):
        """Politique effective = interface (base) surchargée explicitement par l'acteur."""
        base = dict(self.table.get("interfaces", {}).get(
            interface, self.table.get("default", DEFAULT_RIGHTS["default"])))
        ov = (self.table.get("actors") or {}).get(actor)
        if ov:
            base = {**base, **ov}   # l'acteur surcharge (resserre ou élargit) explicitement
        return base

    def check(self, interface, actor, kind, op=None, autonomy=None):
        """Retourne (autorisé: bool, raison: str). Fail-closed sur l'inconnu."""
        pol = self._policy_for(interface, actor)
        kinds = pol.get("kinds", [])
        if kind not in kinds:
            return False, f"interface « {interface} » / acteur « {actor} » : kind « {kind} » non autorisé"
        if kind != "op":
            return True, "ok"
        # kind == op : gating par op + palier d'autonomie.
        if op in (pol.get("deny_ops") or []):
            return False, f"op « {op} » explicitement refusée"
        allow = pol.get("allow_ops")
        if allow is not None and op not in allow:
            return False, f"op « {op} » hors allowlist de « {interface}/{actor} »"
        ceiling = pol.get("op_max_tier", "never")
        if ceiling == "never":
            return False, f"« {interface}/{actor} » n'a aucun droit d'exécution directe (plafond never)"
        if autonomy is not None and _rank(autonomy) > _rank(ceiling):
            return False, (f"op « {op} » (palier {autonomy}) au-dessus du plafond "
                           f"{ceiling} de « {interface}/{actor} »")
        return True, "ok"

    def summary(self):
        ifaces = self.table.get("interfaces", {})
        return {"source": self.source,
                "interfaces": {k: v.get("op_max_tier") for k, v in ifaces.items()},
                "actor_overrides": len(self.table.get("actors") or {})}


class AccessLog:
    """Journal d'accès unifié : 1 ligne JSONL par requête (append-only, thread-safe).

    Best-effort : un échec d'écriture du journal ne casse JAMAIS la requête (mais on
    le signale sur stderr). Les args sont **rédigés** (redact) avant écriture.
    """

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, *, iface_uid, interface, actor, kind, op=None, node=None,
               args=None, allowed=True, deny_reason=None, result=None, duration_ms=None):
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "iface_uid": iface_uid, "iface": interface, "actor": actor,
            "kind": kind, "op": op, "node": node,
            "args": [redact.redact(str(a)) for a in (args or [])],
            "allowed": allowed,
            "duration_ms": duration_ms,
        }
        if deny_reason:
            rec["deny_reason"] = deny_reason
        if result is not None:
            rec["result"] = result
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError as e:
            import sys
            print(f"atlas-core: access-log écriture impossible ({e})", file=sys.stderr)


def result_summary(resp):
    """Réduit une réponse de handler à un résumé loggable (pas de stdout volumineux)."""
    if not isinstance(resp, dict):
        return None
    s = {}
    for k in ("ok", "exit", "action", "tier", "node", "profile"):
        if k in resp:
            s[k] = resp[k]
    if resp.get("error"):
        s["error"] = True
    return s or None
