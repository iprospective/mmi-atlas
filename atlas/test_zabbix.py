#!/usr/bin/env python3
"""test_zabbix — auto-tests du client Zabbix (RM2454, ticket A).

`_call` est mocké : on valide la LOGIQUE (résolution FQDN sans `search`, params des verbes
d'action, garde `manual_close`, dry_run, format prose inchangé) sans accès Zabbix réel.
Lancer : python3 test_zabbix.py   (sortie non nulle si un test échoue)
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zabbix_api as zx

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


def _raises(fn):
    try:
        fn()
        return False
    except (ValueError, zx.ZabbixUnavailable):
        return True


HOSTS = [
    {"hostid": "10", "host": "obs.example.net", "name": "obs"},
    {"hostid": "11", "host": "elrond.abatk.com", "name": "elrond"},
    {"hostid": "12", "host": "node3.example.net", "name": "node3"},
]


def fake_call(hosts=HOSTS, problems=None, capture=None):
    def _f(method, params, timeout=12):
        if capture is not None:
            capture.append((method, params))
        # Garde dure : le piège n°1 interdit tout `search`.
        assert "search" not in params, f"`search` interdit ({method})"
        if method == "host.get":
            filt = params.get("filter", {})
            if "host" in filt:
                return [h for h in hosts if h["host"] in filt["host"]]
            return [dict(h) for h in hosts]          # fetch large
        if method == "problem.get":
            return list(problems or [])
        if method == "template.get":
            return [{"templateid": "999", "host": params["filter"]["host"][0]}]
        if method in ("item.get", "discoveryrule.get"):
            return []
        return {"ok": method}                        # méthodes mutantes
    return _f


# ── résolution d'hôte : FQDN exact, fallback fetch-large, ambiguïté ──
zx._call = fake_call()
check("resolve FQDN exact", zx.resolve_host("obs.example.net")["hostid"] == "10")
check("resolve nom court → FQDN", zx.resolve_host("elrond")["hostid"] == "11")
check("resolve inconnu → None", zx.resolve_host("nexiste.pas") is None)

# ambiguïté : deux hôtes de même préfixe court, aucun match exact → None
zx._call = fake_call(hosts=[{"hostid": "1", "host": "node3.a.net", "name": "a"},
                            {"hostid": "2", "host": "node3.b.net", "name": "b"}])
check("resolve préfixe ambigu → None", zx.resolve_host("node3") is None)

# jamais de `search` : le fetch large est utilisé, la garde du fake n'a pas sauté
cap = []
zx._call = fake_call(capture=cap)
zx.resolve_host("obs")     # court → filtre host court renvoie [] → fetch large
check("resolve sans search (fetch large)",
      any(m == "host.get" and "filter" not in p for m, p in cap))

# ── verbes d'action : params + garde manual_close + dry_run ──
r = zx.ack("555", "vu, en cours", dry_run=True)
check("ack action=6 (ack+message, pas de close)", r["params"]["action"] == 6)
check("ack dry_run n'exécute pas", r["dry_run"] is True and "result" not in r)
check("ack refuse message vide", _raises(lambda: zx.ack("1", "")))

r = zx.lld_run("42", dry_run=True)
check("lld_run task.create type=6",
      r["method"] == "task.create" and r["params"]["type"] == 6
      and r["params"]["request"]["itemids"] == ["42"])

check("disable item → status 1",
      zx.set_item_status("7", False, dry_run=True)["params"]["status"] == 1)
check("enable trigger → status 0",
      zx.set_trigger_status("8", True, dry_run=True)["params"]["status"] == 0)

cap = []
zx._call = fake_call(capture=cap)
r = zx.link_template("obs.example.net", "Template OS Linux", dry_run=True)
check("link_template → host.massadd (hostid+templateid)",
      r["method"] == "host.massadd"
      and r["params"]["hosts"][0]["hostid"] == "10"
      and r["params"]["templates"][0]["templateid"] == "999")
check("link_template dry_run n'exécute pas la mutation",
      not any(m == "host.massadd" for m, p in cap))

# mutation réelle (mockée) : sans dry_run, l'appel part
cap = []
zx._call = fake_call(capture=cap)
zx.set_item_status("7", False, dry_run=False)
check("mutation réelle → appel item.update", any(m == "item.update" for m, p in cap))

# ── host_context : format prose INCHANGÉ (RM2072) ──
probs = [{"eventid": "1", "name": "High memory utilization",
          "severity": "4", "clock": int(time.time()) - 7200}]
zx._call = fake_call(problems=probs)
out = zx.host_context("obs.example.net")
check("host_context entête inchangée",
      out.startswith("Host Zabbix « obs » — 1 problème(s) actif(s) :"))
check("host_context sévérité lisible + ancienneté", "[haute]" in out and "actif depuis" in out)

zx._call = fake_call(problems=[])
check("host_context RAS",
      zx.host_context("obs.example.net").endswith("(RAS côté monitoring)."))
check("host_context host inconnu",
      "introuvable" in zx.host_context("nexiste.pas"))

print("OK" if not FAILED else "ÉCHECS")
sys.exit(1 if FAILED else 0)
