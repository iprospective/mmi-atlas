"""atlas_client — client du socket du cœur Atlas (RM2039).

Utilisé par les interfaces (atlas-bot / atlas-www / atlas-cli) pour soumettre une
intention au cœur et récupérer le résultat. Aucune exécution ni privilège ici : tout
passe par le socket. Le cœur valide, exécute, audite.

    from atlas_client import submit
    resp = submit("tail-log", ["syslog", "20"], actor="telegram:123")
    if resp["ok"]: print(resp["stdout"])
"""
import json
import os
import socket

SOCKET_PATH = os.environ.get("ATLAS_SOCKET", "/run/atlas/atlas.sock")


class CoreUnavailable(RuntimeError):
    """Le socket du cœur est injoignable (daemon arrêté ou droits insuffisants)."""


def _request(req, timeout):
    """Envoie un objet JSON au cœur et retourne sa réponse (dict)."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(SOCKET_PATH)
    except (FileNotFoundError, ConnectionRefusedError, PermissionError) as e:
        raise CoreUnavailable(f"socket cœur injoignable ({SOCKET_PATH}): {e}") from e
    try:
        s.sendall(json.dumps(req).encode("utf-8") + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.split(b"\n", 1)[0] or b"{}")
    finally:
        s.close()


def submit(op, args=(), *, actor="?", node=None, timeout=60):
    """Soumet une intention (op directe, RM2039) au cœur. Retourne la réponse.

    Lève CoreUnavailable si le socket est injoignable.
    """
    return _request({"kind": "op", "actor": actor, "op": op,
                     "args": list(args), "node": node}, timeout)


def submit_event(event, *, actor="?", timeout=90):
    """Soumet un événement de monitoring normalisé au cœur (RM1813).

    Le cœur applique la politique + les garde-fous (moteur de décision) et
    exécute/approuve/notifie selon le palier. `event` = dict normalisé
    (source, host, trigger, severity, state, event_id, item, value, ts).
    """
    return _request({"kind": "event", "actor": actor, "event": dict(event)}, timeout)


def submit_resolve(token, approved, *, actor="?", timeout=90):
    """Résout une approbation P2 en attente (RM1813 #6) : exécute si approuvé."""
    return _request({"kind": "resolve", "actor": actor,
                     "token": token, "approved": bool(approved)}, timeout)


def submit_poll(maxn=50, *, actor="?", timeout=15):
    """Tire les notifications du cœur en attente (alertes + approbations P2)."""
    return _request({"kind": "poll", "actor": actor, "max": maxn}, timeout)


def submit_status(*, actor="?", timeout=10):
    """État du cœur : plafond d'autonomie, diagnostic, compteurs (RM1813)."""
    return _request({"kind": "status", "actor": actor}, timeout)


def submit_diag(node, op="", args=(), *, actor="?", timeout=50):
    """Diagnostic read-only on-target via atlas-safe (RM2050). Op vide → liste les ops."""
    return _request({"kind": "diag", "actor": actor, "node": node,
                     "op": op, "args": list(args)}, timeout)


def submit_aidiag(node, profile="", chat_id=None, *, actor="?", timeout=15):
    """Diagnostic IA MANUEL (RM2072) : ack immédiat, résultat posté plus tard au chat_id."""
    return _request({"kind": "aidiag", "actor": actor, "node": node,
                     "profile": profile, "chat_id": chat_id}, timeout)
