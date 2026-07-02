"""client_dispatch — dispatch des ops d'ACTION du cœur vers atlas-client (RM2092).

Pendant de `safe_dispatch` (read-only → atlas-safe), **côté ACTION**. Le cœur se
connecte en SSH à `atlas-client@<node>` avec une clé **DÉDIÉE** (distincte de la clé
atlas-safe), **`command=` forcée** vers `atlas-client-runner` (frontière 2 de
l'architecture) : même le cœur ne peut déclencher qu'une op **vettée** du nœud, jamais
une commande arbitraire.

Réutilise la résolution de *reachabilité* de `safe_dispatch` (endpoint / proxyjump —
c'est le même nœud), mais **force le compte et la clé atlas-client** (le compte diffère,
pas la route). Limite connue : un nœud routé par `ssh_alias` (config SSH baked-in
user+clé, typiquement atlas-safe) n'est pas encore adressable en action — il faudra un
alias client dédié (serveurs clients via bastion : évolution).
"""
import os

import safe_dispatch as sd

CLIENT_KEY = os.environ.get("ATLAS_CLIENT_KEY", "/opt/atlas/.ssh/atlas-client")
CLIENT_USER = os.environ.get("ATLAS_CLIENT_USER", "atlas-client")

DispatchError = sd.DispatchError


def resolve(node, registry=None):
    """Reachabilité comme atlas-safe, mais compte/clé = atlas-client (forcés).

    On ignore volontairement les `defaults.user`/`key` du registre (orientés read-only)
    et on impose l'identité action."""
    r = dict(sd.resolve(node, registry))
    r["user"] = CLIENT_USER
    r["key"] = CLIENT_KEY
    return r


def run_op(node, op_id, args=(), *, timeout=45, registry=None):
    """Exécute une op d'action `op_id [args]` sur `node` via atlas-client → dict JSON.

    Lève DispatchError si la cible est injoignable / répond hors-protocole."""
    return sd.ssh_json(resolve(node, registry), op_id, args, timeout=timeout)
