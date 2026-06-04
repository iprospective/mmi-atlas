#!/usr/bin/env python3
"""catalogue — framework du catalogue de scripts vetted d'Atlas (RM1816).

Le catalogue est le **chemin privilégié unique** d'Atlas : un registre déclaratif
d'opérations, chacune = un script vetted + un schéma d'arguments strict.

Garanties de sécurité :
  - aucune commande arbitraire : on ne peut exécuter qu'une opération du registre ;
  - aucun argument n'est interpolé dans un shell — exécution en argv (shell=False) ;
  - chaque argument est validé contre un schéma (liste blanche / motif / bornes)
    AVANT exécution ; un argument invalide ⇒ rien n'est lancé ;
  - chaque exécution est journalisée (audit JSONL : qui / quoi / args / exit).

Appelé par le bot (RM1814, commandes manuelles) ET, à terme, par le moteur de
décision autonome (RM1813). L'AUTORISATION (verrou du bot, paliers d'autonomie)
relève de l'appelant ; le catalogue se contente de valider, exécuter, tracer.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OPS_DIR = BASE_DIR / "ops"
DEFAULT_AUDIT_PATH = Path(os.environ.get("ATLAS_AUDIT_PATH",
                                         str(BASE_DIR / "data" / "audit.jsonl")))
DEFAULT_TIMEOUT = 60  # secondes

AUTONOMY_TIERS = ("P0", "P1", "P2", "never")  # cf. RM1813

# Motifs sûrs réutilisables (aucun métacaractère shell, longueur bornée).
RE_SERVICE = re.compile(r"^[A-Za-z0-9@._-]{1,64}$")       # unité systemd / pool FPM
RE_CONTAINER = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")  # nom de conteneur LXC


class ValidationError(ValueError):
    """Argument invalide ou opération inconnue — aucune exécution n'a lieu."""


# ── Spécification d'argument ────────────────────────────────────────────────

@dataclass(frozen=True)
class ArgSpec:
    name: str
    kind: str                       # 'choice' | 'token' | 'int'
    choices: tuple = ()             # pour 'choice'
    pattern: "re.Pattern | None" = None   # pour 'token'
    min: "int | None" = None       # pour 'int'
    max: "int | None" = None
    required: bool = True

    def validate(self, value):
        """Retourne la valeur normalisée (str) sûre, ou lève ValidationError."""
        if value is None or value == "":
            if self.required:
                raise ValidationError(f"argument manquant : {self.name}")
            return None
        v = str(value)
        if self.kind == "choice":
            if v not in self.choices:
                raise ValidationError(
                    f"{self.name}={v!r} hors liste autorisée {list(self.choices)}")
            return v
        if self.kind == "token":
            if not self.pattern or not self.pattern.match(v):
                raise ValidationError(f"{self.name}={v!r} : format invalide")
            return v
        if self.kind == "int":
            try:
                n = int(v)
            except ValueError:
                raise ValidationError(f"{self.name}={v!r} : entier attendu")
            if self.min is not None and n < self.min:
                raise ValidationError(f"{self.name}={n} < min {self.min}")
            if self.max is not None and n > self.max:
                raise ValidationError(f"{self.name}={n} > max {self.max}")
            return str(n)
        raise ValidationError(f"type d'argument inconnu : {self.kind}")


# ── Opération ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Operation:
    id: str
    description: str
    script: Path                   # script vetted à exécuter
    args: tuple = ()               # tuple[ArgSpec]
    autonomy: str = "P2"           # palier par défaut (cf. RM1813)
    target: str = "host"           # 'host' | 'lxc' | 'local'
    reversible: bool = True
    needs_sudo: bool = False       # exécuter via `sudo -n <script>`

    def __post_init__(self):
        if self.autonomy not in AUTONOMY_TIERS:
            raise ValueError(f"{self.id}: palier d'autonomie invalide {self.autonomy!r}")

    def validate_args(self, raw_args):
        """Valide les arguments positionnels → liste de valeurs sûres (str)."""
        if len(raw_args) > len(self.args):
            raise ValidationError(
                f"{len(raw_args) - len(self.args)} argument(s) en trop "
                f"pour l'opération {self.id}")
        out = []
        for i, spec in enumerate(self.args):
            raw = raw_args[i] if i < len(raw_args) else None
            v = spec.validate(raw)
            if v is not None:
                out.append(v)
        return out


# ── Résultat & Catalogue ─────────────────────────────────────────────────────

@dataclass
class Result:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int


class Catalogue:
    """Registre d'opérations + exécution validée + audit."""

    def __init__(self, operations, audit_path=DEFAULT_AUDIT_PATH, runner=None):
        self._ops = {op.id: op for op in operations}
        self.audit_path = Path(audit_path)
        # runner injectable (tests, exécution distante RM1813) ; défaut = local.
        self._runner = runner or self._run_local

    def list(self):
        return [self._ops[k] for k in sorted(self._ops)]

    def get(self, op_id):
        op = self._ops.get(op_id)
        if op is None:
            raise ValidationError(f"opération inconnue : {op_id!r}")
        return op

    def build_argv(self, op, validated):
        prefix = ["sudo", "-n"] if op.needs_sudo else []
        return prefix + [str(op.script)] + validated

    def run(self, op_id, raw_args=(), *, actor="?", node=None, timeout=DEFAULT_TIMEOUT):
        """Valide puis exécute une opération. Journalise et retourne un Result."""
        op = self.get(op_id)
        validated = op.validate_args(list(raw_args))
        if node not in (None, "local", "localhost"):
            # Exécution distante = dispatcher SSH du moteur de décision (RM1813).
            raise ValidationError(
                f"exécution distante (node={node}) pas encore implémentée (RM1813)")
        argv = self.build_argv(op, validated)
        t0 = time.monotonic()
        try:
            proc = self._runner(argv, timeout)
            res = Result(proc.returncode == 0, proc.returncode,
                         proc.stdout or "", proc.stderr or "",
                         int((time.monotonic() - t0) * 1000))
        except subprocess.TimeoutExpired:
            res = Result(False, -1, "", f"timeout après {timeout}s",
                         int((time.monotonic() - t0) * 1000))
        except FileNotFoundError:
            res = Result(False, -1, "", f"script introuvable : {op.script}",
                         int((time.monotonic() - t0) * 1000))
        self._audit(op, validated, actor, node, res)
        return res

    @staticmethod
    def _run_local(argv, timeout):
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, shell=False)

    def _audit(self, op, validated, actor, node, res):
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actor": actor,
            "op": op.id,
            "args": validated,
            "target": op.target,
            "node": node or "local",
            "needs_sudo": op.needs_sudo,
            "exit_code": res.exit_code,
            "ok": res.ok,
            "duration_ms": res.duration_ms,
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
