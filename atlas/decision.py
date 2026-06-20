#!/usr/bin/env python3
"""decision — moteur de décision à paliers d'autonomie d'Atlas (RM1813).

Reçoit un **événement de monitoring normalisé** (Zabbix d'abord, cf. `Event`) et
décide, selon une **politique par règle** (`Rule`), ce qu'Atlas doit faire :

  - **P0 — notify only**   → `notify`   : alerte uniquement, aucune action.
  - **P1 — auto-remédiation allowlistée** → `execute` : lance l'op du catalogue
    (idempotente / réversible), sous garde-fous.
  - **P2 — approbation humaine inline**   → `approve` : demande un OK humain
    (boutons Telegram) avant d'exécuter.
  - **never**              → `notify`   : jamais d'action automatique.

Garde-fous (tous obligatoires pour P1/P2, cf. ticket) :
  - **rate-limit par règle** : au plus `max_per_hour` actions/règle sur 1 h ;
  - **circuit-breaker global** : au-delà de `breaker_max_per_hour` actions toutes
    règles confondues → `escalate` (stop + escalade humaine) ;
  - **anti-flap / cooldown** : on agit sur le `PROBLEM`, on ne ré-agit pas tant que
    l'épisode n'est pas résolu (`OK`) ou que le `cooldown_s` n'est pas écoulé ;
  - **dédup / corrélation** : les événements sont corrélés par épisode
    `(host, trigger)` ; un `PROBLEM` répété sur un épisode déjà traité est
    `suppress`.

Ce module est **pur** (aucune I/O réseau, aucune exécution) : il calcule une
`Decision`. C'est l'appelant (le cœur, RM2039) qui exécute via le catalogue et
qui **valide** la décision en appelant `commit()` une fois l'action réellement
effectuée (immédiatement pour P1, après approbation pour P2). L'état est
sérialisable (`export_state` / `load_state`) pour survivre à un redémarrage.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

# Niveaux de sévérité Zabbix (nom → poids), pour le seuil `min_severity`.
SEVERITY_LEVELS = {
    "not_classified": 0,
    "information": 1,
    "warning": 2,
    "average": 3,
    "high": 4,
    "disaster": 5,
}

TIERS = ("P0", "P1", "P2", "never")
ACTIONS = ("notify", "execute", "approve", "suppress", "escalate")
WINDOW_S = 3600  # fenêtre glissante des garde-fous (1 h)

# Plafond d'autonomie global — borne ce qu'Atlas a le droit de FAIRE, quel que
# soit le palier de la règle. Sécurité : défaut **observe** = diagnostic + alerte
# seulement, aucune action. On relève le plafond explicitement quand on fait
# confiance (« définir ce que peut faire Atlas »).
#   observe  : aucune action       — P1/P2 ramenés à `notify` (+ diagnostic).
#   approve  : approbation humaine  — P1 ramené à `approve` ; P2 inchangé.
#   execute  : autonomie pleine     — P1 `execute`, P2 `approve`.
CEILINGS = ("observe", "approve", "execute")
CEILING_RANK = {"observe": 0, "approve": 1, "execute": 2}


def _severity_level(name: str) -> int:
    """Poids d'une sévérité (insensible à la casse) ; inconnu → 0."""
    return SEVERITY_LEVELS.get(str(name).strip().lower(), 0)


# ── Événement normalisé ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class Event:
    """Événement de monitoring normalisé soumis au moteur."""
    source: str                 # 'zabbix', 'opensvc', 'cron-health'…
    host: str
    trigger: str
    severity: str = "average"   # nom de sévérité (cf. SEVERITY_LEVELS)
    state: str = "PROBLEM"      # 'PROBLEM' | 'OK'
    event_id: str = ""
    item: str = ""
    value: str = ""
    ts: float = 0.0

    @property
    def episode(self) -> str:
        """Clé de corrélation d'un épisode (host + trigger)."""
        return f"{self.host}::{self.trigger}"

    @property
    def is_problem(self) -> bool:
        return str(self.state).strip().upper() == "PROBLEM"


# ── Règle de politique ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class Rule:
    """Une règle de politique : à quels événements elle s'applique, et le palier.

    Le matching est volontairement simple et explicite : motif regex sur le
    trigger (obligatoire), motif optionnel sur l'host, seuil de sévérité mini.
    La première règle qui matche gagne (ordre = priorité).
    """
    id: str
    trigger: str                          # regex (search) sur le libellé du trigger
    tier: str = "P0"                      # P0 | P1 | P2 | never
    op: Optional[str] = None              # op du catalogue pour P1/P2
    args: tuple = ()                      # args littéraux ; {host} substitué depuis l'event
    host: str = ".*"                      # regex (search) sur l'host
    min_severity: str = "not_classified"  # n'applique la règle qu'au-delà de ce seuil
    max_per_hour: int = 3                 # rate-limit par règle
    cooldown_s: int = 300                 # délai mini entre 2 actions d'un même épisode
    diagnose: tuple = ()                  # ops read-only locales (legacy ; cf. RM2050)
    diag_profile: "str | None" = None     # profil de diagnostic ON-TARGET (atlas-safe) :
                                          #   le cœur dispatche ce bundle sur event.host
                                          #   puis passe le résultat à atlas-ai (RM2050)

    def __post_init__(self):
        if self.tier not in TIERS:
            raise ValueError(f"{self.id}: palier invalide {self.tier!r}")
        if self.tier in ("P1", "P2") and not self.op:
            raise ValueError(f"{self.id}: palier {self.tier} sans op du catalogue")
        # compile une fois (objet frozen → on passe par object.__setattr__)
        object.__setattr__(self, "_trigger_re", re.compile(self.trigger))
        object.__setattr__(self, "_host_re", re.compile(self.host))

    def matches(self, ev: Event) -> bool:
        return (
            _severity_level(ev.severity) >= _severity_level(self.min_severity)
            and self._host_re.search(ev.host) is not None
            and self._trigger_re.search(ev.trigger) is not None
        )

    def render_args(self, ev: Event) -> list:
        """Substitue les placeholders sûrs ({host}, {item}) dans les args."""
        subs = {"host": ev.host, "item": ev.item}
        return [str(a).format(**subs) for a in self.args]


# ── Décision ─────────────────────────────────────────────────────────────────

@dataclass
class Decision:
    action: str                 # notify | execute | approve | suppress | escalate
    tier: str
    reason: str
    event: Event
    rule: Optional[Rule] = None
    op: Optional[str] = None
    args: list = field(default_factory=list)
    proposed: Optional[str] = None   # action initiale si bridée par le plafond
    held: bool = False               # True si le plafond a retenu l'action
    diagnose: list = field(default_factory=list)  # [{"op":…, "args":[…]}] read-only

    @property
    def actionable(self) -> bool:
        """Vrai si la décision mène à une exécution (à committer après coup)."""
        return self.action in ("execute", "approve")


# ── État (sérialisable) ──────────────────────────────────────────────────────

@dataclass
class _Episode:
    open_since: Optional[float] = None
    last_action_ts: Optional[float] = None
    acted_count: int = 0


# ── Moteur ───────────────────────────────────────────────────────────────────

class DecisionEngine:
    """Applique la politique + les garde-fous. Pur (pas d'I/O)."""

    def __init__(self, rules, *, now: Callable[[], float] = time.time,
                 breaker_max_per_hour: int = 10, ceiling: str = "observe",
                 default_diagnose=()):
        self.rules = list(rules)
        self._now = now
        self.breaker_max = breaker_max_per_hour
        if ceiling not in CEILINGS:
            raise ValueError(f"plafond d'autonomie invalide : {ceiling!r}")
        self.ceiling = ceiling
        self.default_diagnose = tuple(default_diagnose)
        self._episodes: dict[str, _Episode] = {}
        self._actions_by_rule: dict[str, list] = {}   # rule_id → [ts, …]

    # -- politique ------------------------------------------------------------
    def match_rule(self, ev: Event) -> Optional[Rule]:
        for r in self.rules:
            if r.matches(ev):
                return r
        return None

    # -- garde-fous (lecture seule) ------------------------------------------
    def _prune(self, ts: float):
        cutoff = ts - WINDOW_S
        for rid, lst in self._actions_by_rule.items():
            self._actions_by_rule[rid] = [t for t in lst if t >= cutoff]

    def _rule_count(self, rule_id: str) -> int:
        return len(self._actions_by_rule.get(rule_id, ()))

    def _global_count(self) -> int:
        return sum(len(v) for v in self._actions_by_rule.values())

    # -- plafond d'autonomie & diagnostic ------------------------------------
    def _cap(self, action):
        """Applique le plafond. Retourne (action_finale, retenue?)."""
        if action not in ("execute", "approve"):
            return action, False
        rank = CEILING_RANK[self.ceiling]
        if action == "execute":
            if rank >= 2:
                return "execute", False
            return ("approve", True) if rank == 1 else ("notify", True)
        # approve
        return ("approve", False) if rank >= 1 else ("notify", True)

    def _diagnose_plan(self, ev: Event, rule):
        specs = list(self.default_diagnose)
        if rule and rule.diagnose:
            specs += list(rule.diagnose)
        plan, seen = [], set()
        for op, argtmpl in specs:
            rendered = [str(a).format(host=ev.host, item=ev.item) for a in argtmpl]
            key = (op, tuple(rendered))
            if key not in seen:
                seen.add(key)
                plan.append({"op": op, "args": rendered})
        return plan

    def _mk(self, action, tier, reason, ev, rule, op=None, args=None):
        """Construit la décision : attache le diagnostic + applique le plafond."""
        diagnose = self._diagnose_plan(ev, rule) if ev.is_problem else []
        final, held = self._cap(action)
        proposed = action if held else None
        if held:
            if final == "notify":
                reason += (f" — plafond « {self.ceiling} » : action {tier} retenue "
                           "(diagnostic + alerte seulement)")
            else:
                reason += f" — plafond « {self.ceiling} » : ramené à approbation"
        return Decision(final, tier, reason, ev, rule, op, args or [],
                        proposed=proposed, held=held, diagnose=diagnose)

    # -- décision -------------------------------------------------------------
    def decide(self, ev: Event) -> Decision:
        ts = ev.ts or self._now()
        self._prune(ts)
        ep = self._episodes.setdefault(ev.episode, _Episode())
        rule = self.match_rule(ev)
        tier = rule.tier if rule else "P0"

        # Résolution : l'épisode se referme ; un futur PROBLEM repart à zéro.
        if not ev.is_problem:
            ep.open_since = None
            ep.last_action_ts = None
            ep.acted_count = 0
            return self._mk("notify", tier, "résolution (OK) — épisode refermé", ev, rule)

        # PROBLEM : ouvrir l'épisode si nécessaire.
        if ep.open_since is None:
            ep.open_since = ts

        # Paliers non-actionnables → notify (+ diagnostic).
        if rule is None:
            return self._mk("notify", "P0", "aucune règle — notify par défaut", ev, None)
        if tier == "P0":
            return self._mk("notify", "P0", f"règle {rule.id} : notify only", ev, rule)
        if tier == "never":
            return self._mk("notify", "never",
                            f"règle {rule.id} : action interdite (never)", ev, rule)

        # Actionnable (P1/P2) → garde-fous, PUIS plafond (dans _mk).
        op, args = rule.op, rule.render_args(ev)

        if self._global_count() >= self.breaker_max:
            return self._mk("escalate", tier,
                            f"circuit-breaker : ≥{self.breaker_max} actions/h — "
                            "escalade humaine", ev, rule, op, args)
        if self._rule_count(rule.id) >= rule.max_per_hour:
            return self._mk("escalate", tier,
                            f"rate-limit règle {rule.id} : ≥{rule.max_per_hour}/h — "
                            "escalade humaine", ev, rule, op, args)
        if ep.last_action_ts is not None and (ts - ep.last_action_ts) < rule.cooldown_s:
            return self._mk("suppress", tier,
                            f"anti-flap : action <{rule.cooldown_s}s sur l'épisode "
                            "(en attente de résolution)", ev, rule, op, args)

        if tier == "P1":
            return self._mk("execute", "P1",
                            f"règle {rule.id} : auto-remédiation P1", ev, rule, op, args)
        return self._mk("approve", "P2",
                        f"règle {rule.id} : approbation humaine requise", ev, rule, op, args)

    # -- validation (l'action a réellement eu lieu) --------------------------
    def commit(self, d: Decision):
        """À appeler quand l'action a été exécutée (P1 direct, P2 après OK humain).

        Met à jour les compteurs des garde-fous + l'épisode. Sans effet si la
        décision n'était pas actionnable.
        """
        if not d.actionable or d.rule is None:
            return
        ts = d.event.ts or self._now()
        ep = self._episodes.setdefault(d.event.episode, _Episode())
        ep.last_action_ts = ts
        ep.acted_count += 1
        self._actions_by_rule.setdefault(d.rule.id, []).append(ts)

    # -- persistance ----------------------------------------------------------
    def export_state(self) -> dict:
        return {
            "episodes": {k: vars(v) for k, v in self._episodes.items()},
            "actions_by_rule": self._actions_by_rule,
        }

    def load_state(self, state: dict):
        self._episodes = {k: _Episode(**v) for k, v in state.get("episodes", {}).items()}
        self._actions_by_rule = {k: list(v) for k, v in
                                 state.get("actions_by_rule", {}).items()}
