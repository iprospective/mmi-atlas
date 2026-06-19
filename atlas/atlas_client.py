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


def submit(op, args=(), *, actor="?", node=None, timeout=60):
    """Soumet une intention au cœur. Retourne le dict de réponse JSON.

    Lève CoreUnavailable si le socket est injoignable.
    """
    req = {"actor": actor, "op": op, "args": list(args), "node": node}
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
