#!/usr/bin/env python3
"""test_decision — auto-tests du moteur de décision à paliers (RM1813).

Lancer : python3 test_decision.py   (sortie non nulle si un test échoue)

Horloge factice (`Clock`) → garde-fous (rate-limit, breaker, anti-flap) testés
de façon déterministe sans dépendre du temps réel.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decision import DecisionEngine, Event, Rule  # noqa: E402

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def tick(self, dt):
        self.t += dt


def ev(trigger="FPM pool down", host="web1", sev="high", state="PROBLEM", ts=0.0):
    return Event("zabbix", host, trigger, severity=sev, state=state, ts=ts)


# Politique de test
RULES = [
    Rule("fpm-restart", trigger=r"FPM pool down", tier="P1", op="restart-service",
         args=("{item}",), min_severity="average", max_per_hour=3, cooldown_s=300),
    Rule("lxc-restart", trigger=r"container down", tier="P2", op="restart-lxc",
         args=("{host}",), min_severity="high"),
    Rule("disk-warn", trigger=r"disk", tier="P0"),
    Rule("forbidden", trigger=r"reboot needed", tier="never"),
]


print("— Matching & paliers —")
clk = Clock()
eng = DecisionEngine(RULES, now=clk, breaker_max_per_hour=10)

d = eng.decide(ev("FPM pool down", ts=clk()))
check("P1 → execute", d.action == "execute" and d.tier == "P1" and d.op == "restart-service")
check("anti-flap : pas encore committé, 2e PROBLEM identique sans cooldown→ execute encore",
      eng.decide(ev("FPM pool down", ts=clk())).action == "execute")

d2 = eng.decide(ev("container down", host="srv-x", ts=clk()))
check("P2 → approve", d2.action == "approve" and d2.tier == "P2")
check("P0 → notify", eng.decide(ev("disk 90% full", ts=clk())).action == "notify")
check("never → notify (jamais d'action)",
      eng.decide(ev("reboot needed", ts=clk())).action == "notify")
check("aucune règle → notify par défaut",
      eng.decide(ev("trigger inconnu xyz", ts=clk())).action == "notify")

print("— Seuil de sévérité —")
check("sous le seuil min_severity → pas de match (notify P0)",
      eng.decide(ev("container down", host="srv-x", sev="warning", ts=clk())).action == "notify")

print("— Substitution d'args —")
d3 = eng.decide(ev("FPM pool down", host="web2", ts=clk()))
d3b = eng.decide(Event("zabbix", "web2", "FPM pool down", item="php8.1-fpm", ts=clk()))
check("{item} substitué dans les args", d3b.args == ["php8.1-fpm"])

print("— Anti-flap / cooldown (avec commit) —")
clk2 = Clock()
eng2 = DecisionEngine(RULES, now=clk2)
d = eng2.decide(ev("FPM pool down", host="w", ts=clk2()))
eng2.commit(d)
check("après commit, PROBLEM répété dans le cooldown → suppress",
      eng2.decide(ev("FPM pool down", host="w", ts=clk2())).action == "suppress")
clk2.tick(301)
check("après cooldown écoulé → execute à nouveau",
      eng2.decide(ev("FPM pool down", host="w", ts=clk2())).action == "execute")

print("— Résolution referme l'épisode —")
clk3 = Clock()
eng3 = DecisionEngine(RULES, now=clk3)
eng3.commit(eng3.decide(ev("FPM pool down", host="w", ts=clk3())))
r = eng3.decide(ev("FPM pool down", host="w", state="OK", ts=clk3()))
check("OK → notify (résolution)", r.action == "notify" and "résolution" in r.reason)
check("après résolution, nouveau PROBLEM → execute (cooldown remis à zéro)",
      eng3.decide(ev("FPM pool down", host="w", ts=clk3())).action == "execute")

print("— Rate-limit par règle —")
clk4 = Clock()
eng4 = DecisionEngine(RULES, now=clk4, breaker_max_per_hour=100)
# 3 actions autorisées (max_per_hour=3), épisodes distincts pour éviter le cooldown
for i in range(3):
    d = eng4.decide(ev("FPM pool down", host=f"h{i}", ts=clk4()))
    check(f"action {i+1}/3 sous le rate-limit → execute", d.action == "execute")
    eng4.commit(d)
d = eng4.decide(ev("FPM pool down", host="h3", ts=clk4()))
check("4e action de la règle dans l'heure → escalate (rate-limit)", d.action == "escalate")
clk4.tick(3601)
check("après la fenêtre d'1h → execute à nouveau",
      eng4.decide(ev("FPM pool down", host="h9", ts=clk4())).action == "execute")

print("— Circuit-breaker global —")
clk5 = Clock()
eng5 = DecisionEngine([Rule("any", trigger=r".*", tier="P1", op="restart-service",
                            max_per_hour=100, cooldown_s=0)],
                      now=clk5, breaker_max_per_hour=5)
for i in range(5):
    eng5.commit(eng5.decide(ev("x", host=f"h{i}", ts=clk5())))
check("6e action toutes règles confondues → escalate (breaker)",
      eng5.decide(ev("x", host="h6", ts=clk5())).action == "escalate")

print("— Persistance de l'état —")
state = eng4.export_state()
eng6 = DecisionEngine(RULES, now=clk4, breaker_max_per_hour=100)
eng6.load_state(state)
check("état rechargé → mêmes compteurs de garde-fous",
      eng6.export_state()["actions_by_rule"] == state["actions_by_rule"])

print("— Validation des règles —")
try:
    Rule("bad", trigger="x", tier="P1")  # P1 sans op
    check("Rule P1 sans op rejetée", False)
except ValueError:
    check("Rule P1 sans op rejetée", True)
try:
    Rule("bad", trigger="x", tier="P9")
    check("Rule palier invalide rejeté", False)
except ValueError:
    check("Rule palier invalide rejeté", True)

print("— Politique par défaut (policy.py) —")
from policy import POLICY  # noqa: E402
from operations import OPERATIONS  # noqa: E402
op_ids = {o.id for o in OPERATIONS}
check("POLICY charge sans erreur", len(POLICY) >= 1)
check("toute op P1/P2 de la politique existe au catalogue",
      all(r.op in op_ids for r in POLICY if r.tier in ("P1", "P2")))
peng = DecisionEngine(POLICY, now=Clock())
check("politique : 'FPM pool down' → P1 execute",
      peng.decide(Event("zabbix", "web1", "PHP FPM pool down", item="calicote-74",
                        severity="high")).action == "execute")
check("politique : 'container unreachable' → P2 approve",
      peng.decide(Event("zabbix", "mmi", "LXC container unreachable",
                        severity="high")).action == "approve")
check("politique : 'reboot required' → never (notify)",
      peng.decide(Event("zabbix", "node3", "host reboot required",
                        severity="high")).action == "notify")
check("politique : 'disk 95%' → P0 notify",
      peng.decide(Event("zabbix", "web1", "disk space 95% used",
                        severity="average")).action == "notify")

print("ÉCHEC" if FAILED else "TOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
