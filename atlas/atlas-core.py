#!/usr/bin/env python3
"""atlas-core — le CŒUR d'Atlas (RM2039).

Daemon tournant sous l'utilisateur dédié **`atlas`** : il porte le catalogue, le
sudoers local et le journal d'audit. Il écoute un **socket Unix local** où les
interfaces (atlas-bot / atlas-www / atlas-cli) soumettent une **intention
authentifiée**. Le cœur valide (catalogue), exécute en local (sudo -n pour les ops
privilégiées), audite, et renvoie le résultat.

Le **dispatch SSH** vers les nœuds `atlas-client` = RM1813 (déjà câblé dans le
catalogue : `node != null` lève une erreur tant que le runner distant n'existe pas).

Protocole : 1 requête = 1 objet JSON + '\\n' ; 1 réponse = 1 objet JSON + '\\n'.
  req  {"actor": "telegram:123", "op": "tail-log", "args": ["syslog","20"], "node": null}
  resp {"ok": bool, "exit": int, "stdout": str, "stderr": str,
        "decision": "P0", "duration_ms": int}            | {"ok": false, "error": str}

Sécurité : l'identité de l'**interface** appelante est vérifiée via **SO_PEERCRED**
(uid du process connecté — l'accès au socket est déjà restreint au groupe
`atlas-ifaces` par les permissions 0660). Le champ `actor` est l'identité **end-user**
que l'interface cautionne (Telegram id, session web…) : utilisé pour la policy + l'audit,
jamais pour la confiance (l'interface est, elle, authentifiée par le socket).
"""
import grp
import json
import os
import socket
import struct
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalogue import Catalogue, ValidationError  # noqa: E402
from operations import OPERATIONS                  # noqa: E402

SOCKET_PATH = os.environ.get("ATLAS_SOCKET", "/run/atlas/atlas.sock")
SOCKET_GROUP = os.environ.get("ATLAS_SOCKET_GROUP", "atlas-ifaces")
MAX_REQ = 64 * 1024

CAT = Catalogue(OPERATIONS)


def _peer_uid(conn):
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def _reply(conn, obj):
    conn.sendall(json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n")


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

        op = req.get("op")
        args = req.get("args", [])
        node = req.get("node")
        actor = str(req.get("actor", f"uid:{uid}"))
        if not isinstance(op, str) or not isinstance(args, list):
            return _reply(conn, {"ok": False, "error": "champs op/args invalides"})

        try:
            res = CAT.run(op, [str(a) for a in args], actor=f"{actor} via iface-uid:{uid}", node=node)
            opobj = CAT.get(op)
            _reply(conn, {
                "ok": res.ok, "exit": res.exit_code,
                "stdout": res.stdout, "stderr": res.stderr,
                "decision": getattr(opobj, "autonomy", "?"),
                "duration_ms": res.duration_ms,
            })
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
    sp = Path(SOCKET_PATH)
    sp.parent.mkdir(parents=True, exist_ok=True)
    if sp.exists():
        sp.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sp))
    # socket réservé au groupe des interfaces (atlas-ifaces), 0660.
    try:
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(str(sp), -1, gid)
    except KeyError:
        print(f"atlas-core: groupe {SOCKET_GROUP} absent — socket en mode propriétaire", file=sys.stderr)
    os.chmod(str(sp), 0o660)
    srv.listen(16)
    print(f"atlas-core: écoute {sp} ({len(OPERATIONS)} ops, groupe {SOCKET_GROUP})", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
