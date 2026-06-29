#!/usr/bin/env python3
"""atlas-cli — CLI du catalogue Atlas (RM2041 / épic RM1812).

**Troisième surface d'accès** au catalogue, en complément du bot et de l'UI web.
Deux contextes (cf. docs/atlas-architecture.md) :

  • **Opérateur central** — sur le conteneur `atlas` : relaie au **cœur** via le socket
    local (RM2039). Lance des ops, des diagnostics read-only on-target, interroge l'état.
    Le cœur ré-authentifie (droits partagés RM2079), exécute, audite (journal unifié).
    Contrôle d'accès = qui a un shell sur `atlas` **et** est membre de `atlas-ifaces`.

  • **Runner local** — sur un nœud cible (`--local`, ou si le socket du cœur est absent) :
    valide + exécute les ops vetted **de ce nœud** directement (catalogue + sudoers
    locaux), **sans passer par le cœur**. Pour les ops manuelles / debug local.

Sélection du mode : `--central` / `--local` l'imposent ; sinon **auto** (socket du cœur
joignable → central, sinon local).

Exemples :
    atlas-cli ops                          # liste les opérations du catalogue
    atlas-cli status                       # état du cœur (central)
    atlas-cli run disk-usage               # exécute une op (central ou local selon le contexte)
    atlas-cli run restart-service nginx    # op privilégiée (le cœur applique droits + audit)
    atlas-cli diag mmi tail-log syslog 40  # diagnostic read-only on-target (central → atlas-safe)
    atlas-cli aidiag mmi load              # diagnostic IA à la demande (central)
    atlas-cli --local run service-status nginx   # runner local sur un nœud cible
"""
import argparse
import json
import os
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalogue import Catalogue, ValidationError          # noqa: E402
from operations import OPERATIONS                          # noqa: E402
from atlas_client import (submit, submit_diag, submit_aidiag,  # noqa: E402
                          submit_status, CoreUnavailable)

SOCKET_PATH = os.environ.get("ATLAS_SOCKET", "/run/atlas/atlas.sock")
CAT = Catalogue(OPERATIONS)


def _login():
    try:
        return os.getlogin()
    except OSError:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name


ACTOR = f"cli:{_login()}"


def socket_reachable():
    if not Path(SOCKET_PATH).exists():
        return False
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(2)
        s.connect(SOCKET_PATH)
        s.close()
        return True
    except OSError:
        return False


# ── Rendu ────────────────────────────────────────────────────────────────────

def _emit(obj, as_json):
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2))


def _print_exec(label, ok, exit_code, stdout, stderr, dur, decision=None):
    head = "✅" if ok else f"⚠️  (exit {exit_code})"
    extra = f" [{decision}]" if decision else ""
    print(f"{head} {label}{extra} — {dur} ms")
    body = (stdout or stderr or "").rstrip()
    if body:
        print(body)


# ── Commandes ────────────────────────────────────────────────────────────────

def cmd_ops(args):
    ops = CAT.list()
    if args.json:
        return _emit([{"id": o.id, "description": o.description, "autonomy": o.autonomy,
                       "needs_sudo": o.needs_sudo,
                       "args": [a.name for a in o.args]} for o in ops], True)
    print(f"Catalogue — {len(ops)} opération(s) :")
    for o in ops:
        argnames = " ".join(f"<{a.name}>" + ("" if a.required else "?") for a in o.args)
        print(f"  {o.id:<18} [{o.autonomy}] {o.description}")
        if argnames:
            print(f"  {'':<18}   args: {argnames}")
    return 0


def cmd_run(args, mode):
    op, opargs = args.op, args.args
    if mode == "local":
        if args.node:
            print("✗ --node n'a pas de sens en mode local (runner du nœud courant).", file=sys.stderr)
            return 2
        try:
            res = CAT.run(op, opargs, actor=ACTOR)
        except ValidationError as e:
            print(f"✗ {e}", file=sys.stderr)
            return 2
        if args.json:
            return _emit({"ok": res.ok, "exit": res.exit_code, "stdout": res.stdout,
                          "stderr": res.stderr, "duration_ms": res.duration_ms}, True) or (0 if res.ok else 1)
        _print_exec(f"{op} {' '.join(opargs)}".strip(), res.ok, res.exit_code,
                    res.stdout, res.stderr, res.duration_ms)
        return 0 if res.ok else 1
    # central
    try:
        resp = submit(op, opargs, actor=ACTOR, node=args.node)
    except CoreUnavailable as e:
        print(f"✗ cœur Atlas injoignable — {e}", file=sys.stderr)
        return 3
    if resp.get("error"):
        # cas attendu tant que le dispatch d'action distant n'est pas câblé (RM2042/RM1813)
        print(f"✗ {resp['error']}", file=sys.stderr)
        return 2
    if args.json:
        return _emit(resp, True) or (0 if resp.get("ok") else 1)
    _print_exec(f"{op} {' '.join(opargs)}".strip(), resp.get("ok"), resp.get("exit"),
                resp.get("stdout"), resp.get("stderr"), resp.get("duration_ms", "?"),
                decision=resp.get("decision"))
    return 0 if resp.get("ok") else 1


def cmd_diag(args, mode):
    if mode == "local":
        print("✗ diag on-target est une fonction CENTRALE (passe par le cœur → atlas-safe). "
              "En local, utilise `run` sur les ops read-only du nœud.", file=sys.stderr)
        return 2
    try:
        resp = submit_diag(args.node, args.op or "", args.args, actor=ACTOR)
    except CoreUnavailable as e:
        print(f"✗ cœur Atlas injoignable — {e}", file=sys.stderr)
        return 3
    if resp.get("error"):
        print(f"✗ {resp['error']}", file=sys.stderr)
        return 2
    if args.json:
        return _emit(resp, True) or 0
    if "ops" in resp and not args.op:
        print(f"🔎 {args.node} — ops read-only : {', '.join(resp.get('ops') or [])}")
        return 0
    _print_exec(f"🔎 {args.node} · {args.op}", resp.get("ok"), resp.get("exit"),
                resp.get("stdout"), resp.get("stderr"), resp.get("duration_ms", "?"))
    return 0 if resp.get("ok") else 1


def cmd_aidiag(args, mode):
    if mode == "local":
        print("✗ aidiag est une fonction CENTRALE (cœur + atlas-ai).", file=sys.stderr)
        return 2
    try:
        resp = submit_aidiag(args.node, args.profile or "", None, actor=ACTOR)
    except CoreUnavailable as e:
        print(f"✗ cœur Atlas injoignable — {e}", file=sys.stderr)
        return 3
    if resp.get("error"):
        print(f"✗ {resp['error']}", file=sys.stderr)
        return 2
    print(f"🔎 Diagnostic IA de {resp.get('node', args.node)} "
          f"(profil {resp.get('profile') or 'base'}) lancé.\n"
          f"   Le résultat est posté côté Telegram (le CLI n'a pas de canal de retour async). "
          f"Pour un diag synchrone, utilise `diag`.")
    return 0


def cmd_status(args, mode):
    if mode == "local":
        print("✗ status interroge le CŒUR (mode central).", file=sys.stderr)
        return 2
    try:
        st = submit_status(actor=ACTOR)
    except CoreUnavailable as e:
        print(f"✗ cœur Atlas injoignable — {e}", file=sys.stderr)
        return 3
    if args.json:
        return _emit(st, True) or 0
    print(f"✅ Cœur Atlas en ligne.")
    print(f"  Plafond d'autonomie : {st.get('ceiling')}")
    print(f"  Diagnostic auto     : {'on' if st.get('diagnose') else 'off'}")
    print(f"  Règles / ops        : {st.get('rules')} / {st.get('ops')}")
    print(f"  Approbations attente : {st.get('pending')}  ·  notifs en file : {st.get('queued')}")
    rights = st.get("rights") or {}
    if rights:
        ifaces = ", ".join(f"{k}={v}" for k, v in (rights.get("interfaces") or {}).items())
        print(f"  Droits ({rights.get('source')}) : {ifaces}  ·  overrides acteur : {rights.get('actor_overrides')}")
    if st.get("access_log"):
        print(f"  Journal d'accès     : {st['access_log']}")
    return 0


# ── Main ─────────────────────────────────────────────────────────────────────

def resolve_mode(args):
    if args.local:
        return "local"
    if args.central:
        if not socket_reachable():
            print(f"✗ mode central forcé mais socket du cœur injoignable ({SOCKET_PATH}).", file=sys.stderr)
            sys.exit(3)
        return "central"
    return "central" if socket_reachable() else "local"


def build_parser():
    p = argparse.ArgumentParser(prog="atlas-cli", description="CLI du catalogue Atlas (RM2041).")
    p.add_argument("--local", action="store_true", help="force le runner local (nœud courant)")
    p.add_argument("--central", action="store_true", help="force le mode central (cœur)")
    p.add_argument("--json", action="store_true", help="sortie JSON (scripting)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("ops", help="liste les opérations du catalogue")

    r = sub.add_parser("run", help="exécute une opération")
    r.add_argument("op")
    r.add_argument("args", nargs="*", default=[])
    r.add_argument("--node", help="nœud cible (central ; dispatch d'action distant = RM2042)")

    d = sub.add_parser("diag", help="diagnostic read-only on-target (central)")
    d.add_argument("node")
    d.add_argument("op", nargs="?", default="")
    d.add_argument("args", nargs="*", default=[])

    a = sub.add_parser("aidiag", help="diagnostic IA à la demande (central)")
    a.add_argument("node")
    a.add_argument("profile", nargs="?", default="")

    sub.add_parser("status", help="état du cœur (central)")
    return p


def main():
    args = build_parser().parse_args()
    if args.local and args.central:
        print("✗ --local et --central sont exclusifs.", file=sys.stderr)
        return 2
    if args.cmd == "ops":
        return cmd_ops(args)
    mode = resolve_mode(args)
    return {
        "run": lambda: cmd_run(args, mode),
        "diag": lambda: cmd_diag(args, mode),
        "aidiag": lambda: cmd_aidiag(args, mode),
        "status": lambda: cmd_status(args, mode),
    }[args.cmd]()


if __name__ == "__main__":
    sys.exit(main() or 0)
