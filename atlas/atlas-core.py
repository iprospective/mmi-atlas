#!/usr/bin/env python3
"""atlas-core — le CŒUR d'Atlas (RM2039 + moteur de décision RM1813).

Daemon tournant sous l'utilisateur dédié **`atlas`** : il porte le catalogue, la
politique d'autonomie, le sudoers local et le journal d'audit. Il écoute un
**socket Unix local** où les interfaces (atlas-bot / atlas-www / atlas-cli /
atlas-ingest) soumettent une **intention authentifiée**.

Trois types de message (`kind`) :
  - **op**      (RM2039) : commande directe d'un humain via une interface →
                 valide (catalogue) → exécute (sudo -n si besoin) → audite.
  - **event**   (RM1813) : événement de monitoring normalisé → **moteur de
                 décision** (politique + garde-fous) → notify / execute / approve
                 / suppress / escalate selon le palier.
  - **resolve** (RM1813) : résolution d'une approbation P2 en attente (le tap
                 Telegram « ✅ »/« ✖️ ») → exécute l'op mémorisée si approuvé.

Le **dispatch SSH** vers les nœuds `atlas-client` reste à câbler (catalogue :
`node != null` lève une erreur tant que le runner distant n'existe pas).

Protocole : 1 requête = 1 objet JSON + '\\n' ; 1 réponse = 1 objet JSON + '\\n'.

Sécurité : l'identité de l'**interface** appelante est vérifiée via **SO_PEERCRED**
(accès socket déjà restreint au groupe `atlas-ifaces`, 0660). Le champ `actor` est
l'identité **end-user** que l'interface cautionne (Telegram id, host Zabbix…) :
utilisée pour la policy + l'audit, jamais pour la confiance.
"""
import grp
import json
import os
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalogue import Catalogue, ValidationError  # noqa: E402
from operations import OPERATIONS                  # noqa: E402
from decision import DecisionEngine, Event         # noqa: E402
from policy import POLICY, DEFAULT_DIAGNOSE, DIAG_PROFILES  # noqa: E402
import atlas_ai                                     # noqa: E402
import safe_dispatch                                # noqa: E402

SOCKET_PATH = os.environ.get("ATLAS_SOCKET", "/run/atlas/atlas.sock")
SOCKET_GROUP = os.environ.get("ATLAS_SOCKET_GROUP", "atlas-ifaces")
DATA_DIR = Path(os.environ.get("ATLAS_DATA_DIR", str(Path(__file__).resolve().parent / "data")))
STATE_PATH = Path(os.environ.get("ATLAS_DECISION_STATE", str(DATA_DIR / "decision-state.json")))
DECISIONS_LOG = Path(os.environ.get("ATLAS_DECISIONS_LOG", str(DATA_DIR / "decisions.jsonl")))
APPROVAL_TTL = int(os.environ.get("ATLAS_APPROVAL_TTL", "600"))  # s avant péremption d'un P2
# Plafond d'autonomie : ce qu'Atlas a le DROIT de faire. Défaut « observe » =
# diagnostic + alerte seulement, aucune remédiation (cf. decision.CEILINGS).
CEILING = os.environ.get("ATLAS_AUTONOMY_CEILING", "observe")
# Diagnostic automatique sur PROBLEM (read-only) — actif par défaut.
DIAGNOSE_ON = os.environ.get("ATLAS_DIAGNOSE", "1") not in ("0", "false", "no", "")
# Diagnostic IA on-target (RM2050) : dispatch atlas-safe + raisonnement atlas-ai.
AI_DIAGNOSE_ON = os.environ.get("ATLAS_AI_DIAGNOSE", "1") not in ("0", "false", "no", "")
MAX_REQ = 64 * 1024

CAT = Catalogue(OPERATIONS)
ENGINE = DecisionEngine(POLICY, ceiling=CEILING, default_diagnose=DEFAULT_DIAGNOSE)
_LOCK = threading.Lock()          # sérialise tout le chemin événement/décision
_PENDING = {}                     # token → {"decision": Decision, "ts": float}
_NOTIFS = []                      # file de notifications à tirer par une interface
NOTIF_MAX = 200                   # plafond anti-emballement (on jette les plus vieilles)


# ── État du moteur : persistance (survie au redémarrage) ─────────────────────

def _load_state():
    try:
        ENGINE.load_state(json.loads(STATE_PATH.read_text(encoding="utf-8")))
    except (FileNotFoundError, ValueError):
        pass


def _save_state():
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(ENGINE.export_state(), ensure_ascii=False), encoding="utf-8")
    tmp.replace(STATE_PATH)


def _log_decision(d, extra=None):
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "action": d.action, "tier": d.tier, "reason": d.reason,
        "rule": d.rule.id if d.rule else None,
        "host": d.event.host, "trigger": d.event.trigger,
        "severity": d.event.severity, "state": d.event.state,
        "op": d.op, "args": d.args,
    }
    if extra:
        rec.update(extra)
    DECISIONS_LOG.parent.mkdir(parents=True, exist_ok=True)
    with DECISIONS_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _enqueue_notif(d, token=None, diagnosis=None, extra=None):
    """Empile une notification structurée à tirer par le bot (Telegram).

    Le cœur ne connaît pas Telegram : il publie des champs neutres ; l'interface
    formate + poste (boutons pour `approve`). Appelé sous `_LOCK`.
    """
    n = {
        "action": d.action, "tier": d.tier, "reason": d.reason,
        "host": d.event.host, "trigger": d.event.trigger,
        "severity": d.event.severity, "state": d.event.state,
        "op": d.op, "args": d.args, "token": token,
        "held": d.held, "proposed": d.proposed,
        "diagnosis": diagnosis or [],
        "ts": time.time(),
    }
    if extra:
        n.update(extra)
    _NOTIFS.append(n)
    if len(_NOTIFS) > NOTIF_MAX:
        del _NOTIFS[: len(_NOTIFS) - NOTIF_MAX]


def _push_ai_notif(host, trigger, text):
    """Empile une notif de diagnostic IA (depuis un thread → prend le verrou)."""
    with _LOCK:
        _NOTIFS.append({"action": "ai-diagnosis", "host": host, "trigger": trigger,
                        "text": text, "ts": time.time()})
        if len(_NOTIFS) > NOTIF_MAX:
            del _NOTIFS[: len(_NOTIFS) - NOTIF_MAX]


def _diagnose_async(event, host, trigger, profile):
    """Diagnostic IA on-target (RM2050) : dispatch atlas-safe + raisonnement atlas-ai.

    Tourne dans un thread (le dispatch SSH + l'appel LLM peuvent durer) → n'empêche
    pas la réponse rapide à l'ingest. Le résultat est posté en notif séparée.
    """
    node = host.split(".")[0]   # FQDN Zabbix (bkp.example.net) → nom court (bkp)
    ops = DIAG_PROFILES.get(profile)
    if not ops:
        return
    try:
        diags = safe_dispatch.diagnose_bundle(node, ops)
    except Exception as e:  # noqa: BLE001
        return _push_ai_notif(host, trigger, f"⚠️ collecte on-target impossible : {e}")
    if not any(d.get("ok") for d in diags):
        errs = "; ".join(d.get("error", "") for d in diags if d.get("error"))[:200]
        return _push_ai_notif(host, trigger,
                              f"⚠️ diagnostic on-target indisponible (atlas-safe sur "
                              f"« {node} » ?) — {errs}")
    try:
        text = atlas_ai.diagnose(event, diags)
    except atlas_ai.AIUnavailable as e:
        return _push_ai_notif(host, trigger, f"⚠️ diagnostic IA indisponible : {e}")
    _push_ai_notif(host, trigger, text)


def _maybe_ai_diagnose(d):
    """Lance le diagnostic IA en tâche de fond si la règle le demande (diag_profile)."""
    if not AI_DIAGNOSE_ON or d.action == "suppress":
        return
    rule = d.rule
    if not rule or not getattr(rule, "diag_profile", None):
        return
    event = {"source": d.event.source, "host": d.event.host, "trigger": d.event.trigger,
             "severity": d.event.severity, "state": d.event.state, "item": d.event.item}
    threading.Thread(target=_diagnose_async,
                     args=(event, d.event.host, d.event.trigger, rule.diag_profile),
                     daemon=True).start()


def _new_token():
    return os.urandom(8).hex()


def _prune_pending():
    now = time.time()
    for tok in [t for t, p in _PENDING.items() if now - p["ts"] > APPROVAL_TTL]:
        _PENDING.pop(tok, None)


# ── Socket : identité de l'interface ─────────────────────────────────────────

def _peer_uid(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def _reply(conn, obj):
    conn.sendall(json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n")


# ── Exécution d'une op du catalogue (commun op directe / décision) ───────────

def _run_op(op, args, actor, node=None):
    res = CAT.run(op, [str(a) for a in args], actor=actor, node=node)
    opobj = CAT.get(op)
    return {
        "ok": res.ok, "exit": res.exit_code,
        "stdout": res.stdout, "stderr": res.stderr,
        "decision": getattr(opobj, "autonomy", "?"),
        "duration_ms": res.duration_ms,
    }


def _run_diagnostics(plan, actor):
    """Exécute le plan de diagnostic — **read-only only** (ops palier P0).

    Garde-fou : une op de diagnostic dont le palier n'est pas P0 est refusée (on
    ne « diagnostique » jamais avec une op qui modifie l'état). Tolère les erreurs
    (un diagnostic qui échoue ne bloque pas l'alerte).
    """
    out = []
    if not DIAGNOSE_ON:
        return out
    for step in plan:
        op = step.get("op")
        args = step.get("args", [])
        try:
            opobj = CAT.get(op)
        except ValidationError:
            out.append({"op": op, "ok": False, "output": "op inconnue"})
            continue
        if getattr(opobj, "autonomy", None) != "P0":
            out.append({"op": op, "ok": False,
                        "output": f"refusé : « {op} » non read-only (palier {opobj.autonomy})"})
            continue
        try:
            r = _run_op(op, args, actor=f"diagnose ({actor})")
            out.append({"op": op, "ok": r["ok"],
                        "output": (r["stdout"] or r["stderr"] or "").rstrip()})
        except (ValidationError, Exception) as e:  # noqa: BLE001
            out.append({"op": op, "ok": False, "output": f"erreur : {e}"})
    return out


# ── Handlers par type de message ─────────────────────────────────────────────

def handle_op(req, uid):
    op, args, node = req.get("op"), req.get("args", []), req.get("node")
    actor = str(req.get("actor", f"uid:{uid}"))
    if not isinstance(op, str) or not isinstance(args, list):
        return {"ok": False, "error": "champs op/args invalides"}
    return _run_op(op, args, actor=f"{actor} via iface-uid:{uid}", node=node)


def handle_event(req, uid):
    raw = req.get("event")
    actor = str(req.get("actor", f"uid:{uid}"))
    if not isinstance(raw, dict):
        return {"ok": False, "error": "champ event invalide"}
    try:
        ev = Event(
            source=str(raw.get("source", "?")), host=str(raw.get("host", "?")),
            trigger=str(raw.get("trigger", "")), severity=str(raw.get("severity", "average")),
            state=str(raw.get("state", "PROBLEM")), event_id=str(raw.get("event_id", "")),
            item=str(raw.get("item", "")), value=str(raw.get("value", "")),
            ts=float(raw.get("ts") or time.time()),
        )
    except (TypeError, ValueError) as e:
        return {"ok": False, "error": f"event mal formé : {e}"}

    with _LOCK:
        _prune_pending()
        d = ENGINE.decide(ev)
        # Diagnostic read-only (sauf sur suppress : anti-bruit) — « poser un diagnostic ».
        diag = ([] if d.action == "suppress"
                else _run_diagnostics(d.diagnose, actor=f"event:{ev.host}"))
        out = {"ok": True, "action": d.action, "tier": d.tier, "reason": d.reason,
               "host": ev.host, "trigger": ev.trigger, "op": d.op, "args": d.args,
               "held": d.held, "proposed": d.proposed, "diagnosis": diag}

        if d.action == "execute":
            run = _run_op(d.op, d.args, actor=f"decision:{d.rule.id} ({actor})")
            ENGINE.commit(d)
            _save_state()
            out["result"] = run
            _log_decision(d, {"executed": True, "exit": run.get("exit")})
            _enqueue_notif(d, diagnosis=diag, extra={"exit": run.get("exit"), "ok": run.get("ok")})
        elif d.action == "approve":
            tok = _new_token()
            _PENDING[tok] = {"decision": d, "ts": time.time()}
            out["token"] = tok
            out["ttl"] = APPROVAL_TTL
            _log_decision(d, {"pending_token": tok})
            _enqueue_notif(d, token=tok, diagnosis=diag)
        elif d.action == "suppress":
            _log_decision(d)        # anti-flap/dédup : tracé, pas notifié (anti-bruit)
        else:                       # notify | escalate
            _log_decision(d)
            _enqueue_notif(d, diagnosis=diag)
    # Diagnostic IA on-target (RM2050) — hors verrou (dispatch SSH + LLM lents).
    _maybe_ai_diagnose(d)
    return out


def handle_resolve(req, uid):
    actor = str(req.get("actor", f"uid:{uid}"))
    tok = str(req.get("token", ""))
    approved = bool(req.get("approved"))
    with _LOCK:
        _prune_pending()
        pend = _PENDING.pop(tok, None)
        if pend is None:
            return {"ok": False, "error": "approbation inconnue ou périmée"}
        d = pend["decision"]
        if not approved:
            _log_decision(d, {"approved": False, "by": actor})
            return {"ok": True, "action": "denied", "reason": "approbation refusée",
                    "op": d.op, "args": d.args}
        run = _run_op(d.op, d.args, actor=f"approved:{d.rule.id} by {actor}")
        ENGINE.commit(d)
        _save_state()
        _log_decision(d, {"approved": True, "by": actor, "exit": run.get("exit")})
        return {"ok": True, "action": "executed", "tier": d.tier,
                "op": d.op, "args": d.args, "result": run}


def handle_poll(req, uid):
    """Tire (et draine) les notifications en attente — appelé par le bot (RM1813)."""
    try:
        maxn = min(int(req.get("max", 50)), NOTIF_MAX)
    except (TypeError, ValueError):
        maxn = 50
    with _LOCK:
        batch = _NOTIFS[:maxn]
        del _NOTIFS[:maxn]
    return {"ok": True, "notifs": batch}


def handle_status(req, uid):
    """État du moteur : plafond d'autonomie, diagnostic, compteurs (RM1813)."""
    with _LOCK:
        pending = len(_PENDING)
        queued = len(_NOTIFS)
    return {"ok": True, "ceiling": ENGINE.ceiling, "diagnose": DIAGNOSE_ON,
            "rules": len(POLICY), "ops": len(OPERATIONS),
            "pending": pending, "queued": queued, "approval_ttl": APPROVAL_TTL}


HANDLERS = {"op": handle_op, "event": handle_event, "resolve": handle_resolve,
            "poll": handle_poll, "status": handle_status}


def handle(conn):
    try:
        uid = _peer_uid(conn)
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
            if len(data) > MAX_REQ:
                return _reply(conn, {"ok": False, "error": "requête trop longue"})
        try:
            req = json.loads(data.split(b"\n", 1)[0] or b"{}")
        except Exception:
            return _reply(conn, {"ok": False, "error": "JSON invalide"})

        kind = req.get("kind", "op")  # défaut op = rétro-compat RM2039
        fn = HANDLERS.get(kind)
        if fn is None:
            return _reply(conn, {"ok": False, "error": f"type de message inconnu : {kind}"})
        try:
            _reply(conn, fn(req, uid))
        except ValidationError as e:
            _reply(conn, {"ok": False, "error": str(e)})
    except Exception as e:  # un client défaillant ne doit pas tuer le daemon
        try:
            _reply(conn, {"ok": False, "error": f"erreur interne: {e}"})
        except Exception:
            pass
    finally:
        conn.close()


def main():
    _load_state()
    sp = Path(SOCKET_PATH)
    sp.parent.mkdir(parents=True, exist_ok=True)
    if sp.exists():
        sp.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sp))
    try:
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(str(sp), -1, gid)
    except KeyError:
        print(f"atlas-core: groupe {SOCKET_GROUP} absent — socket en mode propriétaire", file=sys.stderr)
    os.chmod(str(sp), 0o660)
    srv.listen(16)
    print(f"atlas-core: écoute {sp} ({len(OPERATIONS)} ops, {len(POLICY)} règles, "
          f"plafond={ENGINE.ceiling}, diagnostic={'on' if DIAGNOSE_ON else 'off'}, "
          f"groupe {SOCKET_GROUP})", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
