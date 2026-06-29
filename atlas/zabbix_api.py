#!/usr/bin/env python3
"""zabbix_api — contexte Zabbix pour enrichir le diagnostic IA (RM2072).

Read-only. Auth par **token API** (ATLAS_ZABBIX_TOKEN_SECRET), en-tête Bearer
(Zabbix 6.4+/7.0). Donne au LLM la **tendance** (problèmes actifs du host + leur
ancienneté) en plus du snapshot on-target → distingue vrai problème et faux positif.
Dégrade proprement (ZabbixUnavailable) si non configuré / injoignable.
"""
import json
import os
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


def _hostid(name):
    short = name.split(".")[0]
    for q in ({"filter": {"host": [name]}}, {"filter": {"host": [short]}},
              {"search": {"name": short}}):
        hs = _call("host.get", {**q, "output": ["hostid", "name"]})
        if hs:
            return hs[0]["hostid"], hs[0].get("name") or name
    return None, name


def host_context(host_name):
    """Texte lisible : problèmes ACTIFS du host (sévérité + ancienneté = tendance).

    Lève ZabbixUnavailable si l'API est down / non configurée.
    """
    hid, disp = _hostid(host_name)
    if not hid:
        return f"(host « {host_name} » introuvable dans Zabbix)"
    probs = _call("problem.get", {
        "hostids": [hid], "recent": False, "output": "extend",
        "sortfield": ["eventid"], "sortorder": "DESC", "limit": 25}) or []
    now = int(time.time())
    if not probs:
        return f"Host Zabbix « {disp} » : aucun problème actif (RAS côté monitoring)."
    lines = [f"Host Zabbix « {disp} » — {len(probs)} problème(s) actif(s) :"]
    for p in probs:
        age = max(0, now - int(p.get("clock", now)))
        d, h, m = age // 86400, (age % 86400) // 3600, (age % 3600) // 60
        dur = (f"{d}j{h}h" if d else (f"{h}h{m:02d}" if h else f"{m}min"))
        lines.append(f"  • [{SEV.get(str(p.get('severity')), '?')}] "
                     f"{p.get('name')} — actif depuis {dur}")
    return "\n".join(lines)
