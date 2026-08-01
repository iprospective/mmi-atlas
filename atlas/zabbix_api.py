#!/usr/bin/env python3
"""zabbix_api — client Zabbix d'atlas.

Deux niveaux :
- **read-only prose** pour enrichir le diagnostic IA (`host_context`, RM2072) — inchangé ;
- **structuré + verbes d'action** pour les orchestrateurs (RM2454, ticket A).

Auth par **token API** (`ATLAS_ZABBIX_TOKEN_SECRET`), en-tête Bearer (Zabbix 6.4+/7.x).
Dégrade proprement (`ZabbixUnavailable`) si non configuré / injoignable.

Pièges encodés ici (cf. `knowledge/zabbix/api.md`) :
- **jamais `search`** (faux négatifs/positifs SILENCIEUX) → fetch large + filtre client ;
- **hôtes en FQDN** → résolution du nom technique exact d'abord ;
- **`event.acknowledge`** : `action` est un bitmask (1=close, 2=ack, 4=message…). On acquitte
  en `action=6` (ack+message) et **jamais** le bit *close* par défaut (garde `manual_close`).

Les verbes d'action acceptent `dry_run=True` : ils retournent l'appel prévu sans l'exécuter.
Aucun secret n'est loggué (le token ne sort que dans l'en-tête HTTP).
"""
import argparse
import json
import os
import sys
import time
import urllib.request

URL = (os.environ.get("ATLAS_ZABBIX_URL") or "").strip()
TOKEN = (os.environ.get("ATLAS_ZABBIX_TOKEN_SECRET")
         or os.environ.get("ATLAS_ZABBIX_TOKEN") or "").strip()
SEV = {"0": "non classée", "1": "info", "2": "warning",
       "3": "moyenne", "4": "haute", "5": "désastre"}


class ZabbixUnavailable(RuntimeError):
    pass


def _call(method, params, timeout=12):
    if not URL or not TOKEN:
        raise ZabbixUnavailable("ATLAS_ZABBIX_URL / token non configurés")
    body = json.dumps({"jsonrpc": "2.0", "method": method,
                       "params": params, "id": 1}).encode("utf-8")
    req = urllib.request.Request(URL, data=body, headers={
        "Content-Type": "application/json-rpc",
        "Authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read())
    except Exception as e:  # noqa: BLE001
        raise ZabbixUnavailable(f"API Zabbix injoignable : {e}") from e
    if isinstance(d, dict) and d.get("error"):
        err = d["error"]
        raise ZabbixUnavailable(str(err.get("data") or err.get("message") or err))
    return d.get("result")


# ── Résolution d'hôte (piège n°2 : FQDN ; jamais de `search` nu) ──────────────

def resolve_host(name):
    """{'hostid','host','name'} de l'hôte, ou None si introuvable/ambigu.

    D'abord match **exact** sur le champ technique `host` (FQDN, puis nom court). Sinon
    fetch **large** + filtre client (jamais `search` : faux négatifs/positifs silencieux).
    Un préfixe court ambigu (plusieurs candidats) → None plutôt qu'un « 1er venu » hasardeux.
    """
    for cand in (name, name.split(".")[0]):
        hs = _call("host.get", {"filter": {"host": [cand]},
                                "output": ["hostid", "host", "name"]})
        if hs:
            h = hs[0]
            return {"hostid": h["hostid"], "host": h["host"],
                    "name": h.get("name") or h["host"]}
    allh = _call("host.get", {"output": ["hostid", "host", "name"]}) or []
    nl, short = name.lower(), name.split(".")[0].lower()
    exact = [h for h in allh
             if h["host"].lower() == nl or (h.get("name") or "").lower() == nl]
    cands = exact or [h for h in allh if h["host"].lower().split(".")[0] == short]
    if len(cands) == 1:
        h = cands[0]
        return {"hostid": h["hostid"], "host": h["host"],
                "name": h.get("name") or h["host"]}
    return None


# ── Lectures structurées ─────────────────────────────────────────────────────

def _dur(age):
    d, h, m = age // 86400, (age % 86400) // 3600, (age % 3600) // 60
    return f"{d}j{h}h" if d else (f"{h}h{m:02d}" if h else f"{m}min")


def _problems_for(hostids, limit):
    params = {"output": "extend", "recent": False, "sortfield": ["eventid"],
              "sortorder": "DESC", "limit": limit}
    if hostids:
        params["hostids"] = hostids
    raw = _call("problem.get", params) or []
    now = int(time.time())
    out = []
    for p in raw:
        clock = int(p.get("clock", now))
        age = max(0, now - clock)
        sev = str(p.get("severity"))
        out.append({"eventid": p.get("eventid"), "name": p.get("name"),
                    "severity": int(sev) if sev.isdigit() else None,
                    "severity_label": SEV.get(sev, "?"), "clock": clock,
                    "age_seconds": age, "age_human": _dur(age)})
    return out


def get_problems(host=None, limit=100):
    """Problèmes ACTIFS (triggers en PROBLEM), structurés. Fetch large + filtre client."""
    hostids = None
    if host:
        h = resolve_host(host)
        if not h:
            return []
        hostids = [h["hostid"]]
    return _problems_for(hostids, limit)


def get_host(name):
    """État structuré d'un hôte : identité, statut, interfaces, nb de problèmes actifs."""
    h = resolve_host(name)
    if not h:
        return None
    full = _call("host.get", {"hostids": [h["hostid"]],
                              "output": ["hostid", "host", "name", "status"],
                              "selectInterfaces": ["ip", "type", "available"]}) or []
    info = full[0] if full else {}
    return {"hostid": h["hostid"], "host": h["host"], "name": h["name"],
            "status": "monitored" if str(info.get("status")) == "0" else "disabled",
            "interfaces": info.get("interfaces", []),
            "active_problems": len(_problems_for([h["hostid"]], 1000))}


def get_items(host, unsupported=False):
    """Items de l'hôte (structurés). `unsupported=True` inclut les items non supportés."""
    h = resolve_host(host)
    if not h:
        return []
    items = _call("item.get", {"hostids": [h["hostid"]], "sortfield": "name",
                               "output": ["itemid", "name", "key_", "lastvalue",
                                          "state", "status", "units"]}) or []
    if not unsupported:
        items = [i for i in items if str(i.get("state")) == "0"]  # 0=normal 1=unsupported
    return items


def get_lld(host):
    """Règles de découverte (LLD) de l'hôte, structurées."""
    h = resolve_host(host)
    if not h:
        return []
    return _call("discoveryrule.get", {"hostids": [h["hostid"]], "sortfield": "name",
                                       "output": ["itemid", "name", "key_",
                                                  "status", "state"]}) or []


# ── Verbes d'action (API only, jamais SQL ; `dry_run` supporté ; tracé côté appelant) ──

def _action(method, params, dry_run):
    """Exécute ou (dry_run) décrit l'appel. Retour structuré uniforme."""
    if dry_run:
        return {"dry_run": True, "method": method, "params": params}
    return {"dry_run": False, "method": method, "result": _call(method, params)}


def lld_run(ruleid, dry_run=False):
    """LLD « Execute now » (`task.create` type=6) sur une règle de découverte."""
    return _action("task.create",
                   {"type": 6, "request": {"itemids": [str(ruleid)]}}, dry_run)


def ack(eventid, message, dry_run=False):
    """Acquitte un événement + message (`action=6`). N'ajoute JAMAIS le bit *close* (1)
    par défaut : garde `manual_close` (piège des templates Linux, cf. knowledge)."""
    if not message:
        raise ValueError("ack : message requis")
    return _action("event.acknowledge",
                   {"eventids": [str(eventid)], "action": 6, "message": message}, dry_run)


def set_item_status(itemid, enabled, dry_run=False):
    """Active (enabled=True → status 0) ou désactive (status 1) un item."""
    return _action("item.update",
                   {"itemid": str(itemid), "status": 0 if enabled else 1}, dry_run)


def set_trigger_status(triggerid, enabled, dry_run=False):
    """Active / désactive un trigger."""
    return _action("trigger.update",
                   {"triggerid": str(triggerid), "status": 0 if enabled else 1}, dry_run)


def link_template(host, template, dry_run=False):
    """Lie un template (par son nom technique) à un hôte."""
    h = resolve_host(host)
    if not h:
        raise ZabbixUnavailable(f"hôte introuvable : {host}")
    ts = _call("template.get", {"filter": {"host": [template]},
                                "output": ["templateid", "host"]}) or []
    if not ts:
        raise ZabbixUnavailable(f"template introuvable : {template}")
    return _action("host.massadd",
                   {"hosts": [{"hostid": h["hostid"]}],
                    "templates": [{"templateid": ts[0]["templateid"]}]}, dry_run)


# ── Prose pour le diagnostic IA (RM2072) — wrapper mince, format INCHANGÉ ─────

def host_context(host_name):
    """Texte lisible : problèmes ACTIFS du host (sévérité + ancienneté = tendance).

    Lève ZabbixUnavailable si l'API est down / non configurée. Format identique à l'origine
    (RM2072) : consommé tel quel par le bundle de diagnostic (`atlas-core`).
    """
    h = resolve_host(host_name)
    if not h:
        return f"(host « {host_name} » introuvable dans Zabbix)"
    probs = _problems_for([h["hostid"]], 25)
    disp = h["name"]
    if not probs:
        return f"Host Zabbix « {disp} » : aucun problème actif (RAS côté monitoring)."
    lines = [f"Host Zabbix « {disp} » — {len(probs)} problème(s) actif(s) :"]
    for p in probs:
        lines.append(f"  • [{p['severity_label']}] {p['name']} "
                     f"— actif depuis {p['age_human']}")
    return "\n".join(lines)


# ── Mini-CLI de test direct (l'exposition orchestrateur = catalogue, RM2496) ──

def main(argv=None):
    ap = argparse.ArgumentParser(prog="zabbix_api",
                                 description="Client Zabbix atlas (test direct).")
    ap.add_argument("-n", "--dry-run", action="store_true",
                    help="verbes d'action : décrire l'appel sans l'exécuter")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("host").add_argument("host")
    pi = sub.add_parser("items")
    pi.add_argument("host")
    pi.add_argument("--unsupported", action="store_true")
    pp = sub.add_parser("problems")
    pp.add_argument("host", nargs="?")
    sub.add_parser("lld").add_argument("host")
    sub.add_parser("lld-run").add_argument("ruleid")
    pa = sub.add_parser("ack")
    pa.add_argument("eventid")
    pa.add_argument("message")
    for verb in ("enable", "disable"):
        pv = sub.add_parser(verb)
        pv.add_argument("kind", choices=["item", "trigger"])
        pv.add_argument("id")
    pl = sub.add_parser("link-template")
    pl.add_argument("host")
    pl.add_argument("template")
    a = ap.parse_args(argv)

    def emit(obj):
        print(json.dumps(obj, ensure_ascii=False, indent=2))

    try:
        if a.cmd == "host":
            emit(get_host(a.host))
        elif a.cmd == "items":
            emit(get_items(a.host, unsupported=a.unsupported))
        elif a.cmd == "problems":
            emit(get_problems(a.host))
        elif a.cmd == "lld":
            emit(get_lld(a.host))
        elif a.cmd == "lld-run":
            emit(lld_run(a.ruleid, dry_run=a.dry_run))
        elif a.cmd == "ack":
            emit(ack(a.eventid, a.message, dry_run=a.dry_run))
        elif a.cmd in ("enable", "disable"):
            fn = set_item_status if a.kind == "item" else set_trigger_status
            emit(fn(a.id, a.cmd == "enable", dry_run=a.dry_run))
        elif a.cmd == "link-template":
            emit(link_template(a.host, a.template, dry_run=a.dry_run))
        return 0
    except (ZabbixUnavailable, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
