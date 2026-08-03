#!/usr/bin/env python3
"""zabbix_ops — opérations catalogue Zabbix (RM2496, ticket B).

Expose les lectures structurées + verbes d'action de `zabbix_api` (RM2454) comme
`Operation`s du catalogue atlas → pilotables via atlas-cli / atlas-www, avec plafonds
d'autonomie (P0 lecture · P1 réversible · P2 disruptif) et audit-trail.

`target='api'` : le runner du catalogue appelle le **handler Python** (aucun script
shell, aucun sudo). Les verbes mutants honorent `dry_run` (poussé par le catalogue).
Aucun secret n'est manipulé ici : `zabbix_api` lit le token dans l'environnement.
"""
import re

from catalogue import ArgSpec, Operation
import zabbix_api as zx

# Motifs de validation (ré-validés avant tout appel API).
RE_ZBX_ID = re.compile(r"^[0-9]{1,20}$")                    # eventid / itemid / ruleid…
RE_ZBX_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$")
RE_ZBX_TEMPLATE = re.compile(r"^[A-Za-z0-9 ._/()+-]{1,128}$")
RE_ZBX_MSG = re.compile(r"^[^\x00-\x1f]{1,200}$")           # message d'ack (pas de ctrl)


def _id(name):
    return ArgSpec(name, "token", pattern=RE_ZBX_ID)


def _host(name="host", required=True):
    return ArgSpec(name, "token", pattern=RE_ZBX_HOST, required=required)


# ── Handlers : (args:list[str], dry_run:bool) -> dict JSON-sérialisable ──────

def _h_host(a, dry):          return {"host": zx.get_host(a[0])}
def _h_items(a, dry):         return {"items": zx.get_items(a[0])}
def _h_problems(a, dry):      return {"problems": zx.get_problems(a[0] if a else None)}
def _h_lld(a, dry):           return {"lld": zx.get_lld(a[0])}
def _h_lld_run(a, dry):       return zx.lld_run(a[0], dry_run=dry)
def _h_ack(a, dry):           return zx.ack(a[0], a[1], dry_run=dry)
def _h_item_enable(a, dry):   return zx.set_item_status(a[0], True, dry_run=dry)
def _h_item_disable(a, dry):  return zx.set_item_status(a[0], False, dry_run=dry)
def _h_trig_enable(a, dry):   return zx.set_trigger_status(a[0], True, dry_run=dry)
def _h_trig_disable(a, dry):  return zx.set_trigger_status(a[0], False, dry_run=dry)
def _h_link(a, dry):          return zx.link_template(a[0], a[1], dry_run=dry)


def _op(op_id, desc, handler, args=(), autonomy="P0"):
    return Operation(id=op_id, description=desc, handler=handler, args=args,
                     autonomy=autonomy, target="api", reversible=True, needs_sudo=False)


ZABBIX_OPERATIONS = (
    # ── Lecture (P0) ─────────────────────────────────────────────────────────
    _op("zbx-host", "Zabbix : état structuré d'un hôte", _h_host, (_host(),)),
    _op("zbx-items", "Zabbix : items + dernières valeurs d'un hôte", _h_items, (_host(),)),
    _op("zbx-problems", "Zabbix : problèmes actifs (hôte optionnel)", _h_problems,
        (_host(required=False),)),
    _op("zbx-lld", "Zabbix : règles de découverte (LLD) d'un hôte", _h_lld, (_host(),)),
    # ── Action réversible / sûre (P1) ────────────────────────────────────────
    _op("zbx-lld-run", "Zabbix : LLD « execute now » sur une règle", _h_lld_run,
        (_id("ruleid"),), autonomy="P1"),
    _op("zbx-ack", "Zabbix : acquitter un événement + message (garde manual_close)",
        _h_ack, (_id("eventid"), ArgSpec("message", "token", pattern=RE_ZBX_MSG)),
        autonomy="P1"),
    _op("zbx-item-enable", "Zabbix : réactiver un item", _h_item_enable,
        (_id("itemid"),), autonomy="P1"),
    _op("zbx-trigger-enable", "Zabbix : réactiver un trigger", _h_trig_enable,
        (_id("triggerid"),), autonomy="P1"),
    # ── Action disruptive (P2 : approbation) ─────────────────────────────────
    _op("zbx-item-disable", "Zabbix : désactiver un item", _h_item_disable,
        (_id("itemid"),), autonomy="P2"),
    _op("zbx-trigger-disable", "Zabbix : désactiver un trigger", _h_trig_disable,
        (_id("triggerid"),), autonomy="P2"),
    _op("zbx-link-template", "Zabbix : lier un template à un hôte", _h_link,
        (_host(), ArgSpec("template", "token", pattern=RE_ZBX_TEMPLATE)), autonomy="P2"),
)
