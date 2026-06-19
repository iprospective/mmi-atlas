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
from policy import POLICY                          # noqa: E402

SOCKET_PATH = os.environ.get("ATLAS_SOCKET", "/run/atlas/atlas.sock")
SOCKET_GROUP = os.environ.get("ATLAS_SOCKET_GROUP", "atlas-ifaces")
DATA_DIR = Path(os.environ.get("ATLAS_DATA_DIR", str(Path(__file__).resolve().parent / "data")))
STATE_PATH = Path(os.environ.get("ATLAS_DECISION_STATE", str(DATA_DIR / "decision-state.json")))
DECISIONS_LOG = Path(os.environ.get("ATLAS_DECISIONS_LOG", str(DATA_DIR / "decisions.jsonl")))
APPROVAL_TTL = int(os.environ.get("ATLAS_APPROVAL_TTL", "600"))  # s avant péremption d'un P2
MAX_REQ = 64 * 1024

CAT = Catalogue(OPERATIONS)
ENGINE = DecisionEngine(POLICY)
_LOCK = threading.Lock()          # sérialise tout le chemin événement/décision
_PENDING = {}                     # token → {"decision": Decision, "ts": float}


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
        out = {"ok": True, "action": d.action, "tier": d.tier, "reason": d.reason,
               "host": ev.host, "trigger": ev.trigger, "op": d.op, "args": d.args}

        if d.action == "execute":
            run = _run_op(d.op, d.args, actor=f"decision:{d.rule.id} ({actor})")
            ENGINE.commit(d)
            _save_state()
            out["result"] = run
            _log_decision(d, {"executed": True, "exit": run.get("exit")})
        elif d.action == "approve":
            tok = _new_token()
            _PENDING[tok] = {"decision": d, "ts": time.time()}
            out["token"] = tok
            out["ttl"] = APPROVAL_TTL
            _log_decision(d, {"pending_token": tok})
        else:  # notify | suppress | escalate
            _log_decision(d)
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


HANDLERS = {"op": handle_op, "event": handle_event, "resolve": handle_resolve}


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
          f"groupe {SOCKET_GROUP})", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
