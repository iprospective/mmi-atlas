"""safe_dispatch — dispatch des ops read-only du cœur vers atlas-safe (RM2050).

Le cœur se connecte en SSH à `atlas-safe@<endpoint>` avec une clé **command=-forcée** :
il ne peut déclencher QUE le runner read-only du nœud. On envoie `<op_id> [args]`,
on récupère le JSON de réponse.

**Registre node → {endpoint, clé, user, proxyjump}** (RM2050) : permet de viser
au-delà du vrack interne (serveurs clients). Source : fichier JSON `ATLAS_NODES`
(défaut /opt/atlas/nodes.json). Un nœud absent du registre retombe sur le défaut
interne : `<node>.<domain>` + la clé par défaut (une seule clé pour l'instant ; le
champ `key` permet d'en dédier une par client plus tard, sans réarchitecturer).
"""
import json
import os
import shlex
import subprocess

DEF_KEY = os.environ.get("ATLAS_SAFE_KEY", "/opt/atlas/.ssh/atlas-safe")
DEF_USER = os.environ.get("ATLAS_SAFE_USER", "atlas-safe")
DEF_DOMAIN = os.environ.get("ATLAS_NODE_DOMAIN", "lan")          # <node>.lan (vrack)
REGISTRY_PATH = os.environ.get("ATLAS_NODES", "/opt/atlas/nodes.json")


class DispatchError(RuntimeError):
    pass


def _load_registry():
    try:
        return json.loads(open(REGISTRY_PATH, encoding="utf-8").read())
    except (FileNotFoundError, ValueError):
        return {}


def resolve(node, registry=None):
    """Résout un nœud → {user, host, key, proxyjump}. Défaut interne si absent du registre."""
    reg = registry if registry is not None else _load_registry()
    d = reg.get("defaults", {})
    user = d.get("user", DEF_USER)
    key = d.get("key", DEF_KEY)
    domain = d.get("domain", DEF_DOMAIN)
    e = (reg.get("nodes") or {}).get(node, {})
    return {
        "user": e.get("user", user),
        "host": e.get("endpoint", f"{node}.{domain}"),
        "key": e.get("key", key),
        "proxyjump": e.get("proxyjump"),
    }


def run_op(node, op_id, args=(), *, timeout=30, registry=None):
    """Exécute une op read-only sur `node` via atlas-safe. Retourne le dict JSON."""
    r = resolve(node, registry)
    target = f"{r['user']}@{r['host']}"
    remote = shlex.join([op_id, *[str(a) for a in args]])
    cmd = ["ssh", "-i", r["key"], "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10"]
    if r.get("proxyjump"):
        cmd += ["-J", r["proxyjump"]]
    cmd += [target, remote]
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
    registry = _load_registry()   # une seule lecture pour tout le bundle
    out = []
    for op_id, args in ops:
        try:
            out.append(run_op(node, op_id, args, timeout=timeout, registry=registry))
        except DispatchError as e:
            out.append({"ok": False, "op": op_id, "args": list(args), "error": str(e)})
    return out
