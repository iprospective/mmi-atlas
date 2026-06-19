"""safe_dispatch — dispatch des ops read-only du cœur vers atlas-safe (RM2050).

Le cœur (user `atlas`) se connecte en SSH à `atlas-safe@<nœud>.lan` avec sa clé
**command=-forcée** : il ne peut déclencher QUE le runner read-only du nœud. On
envoie `<op_id> [args]`, on récupère le JSON de réponse.
"""
import json
import os
import shlex
import subprocess

SSH_KEY = os.environ.get("ATLAS_SAFE_KEY", "/opt/atlas/.ssh/atlas-safe")
SSH_USER = os.environ.get("ATLAS_SAFE_USER", "atlas-safe")
NODE_DOMAIN = os.environ.get("ATLAS_NODE_DOMAIN", "lan")   # <nœud>.lan (vrack)


class DispatchError(RuntimeError):
    pass


def run_op(node, op_id, args=(), *, timeout=30):
    """Exécute une op read-only sur `node` via atlas-safe. Retourne le dict JSON."""
    target = f"{SSH_USER}@{node}.{NODE_DOMAIN}"
    remote = shlex.join([op_id, *[str(a) for a in args]])
    cmd = ["ssh", "-i", SSH_KEY, "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
           target, remote]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise DispatchError(f"timeout SSH {target}") from e
    line = (p.stdout or "").strip().splitlines()[-1:] or [""]
    try:
        return json.loads(line[0])
    except ValueError as e:
        raise DispatchError(
            f"réponse non-JSON de {target} (rc={p.returncode}): "
            f"{(p.stdout + p.stderr)[:200]}") from e


def diagnose_bundle(node, ops, *, timeout=30):
    """ops = liste de (op_id, args). Retourne la liste des réponses (tolère les échecs)."""
    out = []
    for op_id, args in ops:
        try:
            out.append(run_op(node, op_id, args, timeout=timeout))
        except DispatchError as e:
            out.append({"ok": False, "op": op_id, "args": list(args), "error": str(e)})
    return out
