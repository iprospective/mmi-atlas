#!/usr/bin/env python3
"""redact — masquage des données sensibles avant envoi au LLM (RM2050).

Dès qu'un diagnostic peut contenir des données client (logs, configs), on **masque**
avant de l'envoyer à un modèle — surtout cloud. Cloisonnement : pas de secrets ni de
PII qui fuient vers ollama.com.

Volontairement **conservateur** : on masque ce qui est clairement secret/PII (clés
privées, identifiants `clé=valeur`, e-mails, IP) sans charcuter le contexte utile au
diagnostic (noms d'unités, ports, états, chemins). Mieux vaut un diagnostic lisible
qu'un texte caviardé inexploitable.
"""
import re

_RULES = [
    # Blocs de clé privée (PEM) — multi-lignes.
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                re.DOTALL), "[CLÉ PRIVÉE]"),
    # Identifiants clé=valeur / clé: valeur (password, token, secret, api_key…).
    (re.compile(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
                r"auth|bearer|private[_-]?key)\b\s*[=:]\s*[^\s,;'\"]+"), r"\1=[CAVIARDÉ]"),
    # URLs avec identifiants : scheme://user:pass@host
    (re.compile(r"\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[CAVIARDÉ]@"),
    # E-mails.
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    # IPv4 (4 octets — ne touche pas aux versions type 10.6.23 ni aux ports).
    (re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), "[IP]"),
    # IPv6 (formes courantes).
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}\b"), "[IPv6]"),
]


def redact(text):
    """Retourne `text` avec les éléments sensibles masqués."""
    if not text:
        return text
    for pat, repl in _RULES:
        text = pat.sub(repl, text)
    return text


def redact_diagnostics(diags):
    """Applique redact() sur les champs texte de chaque réponse de diagnostic."""
    out = []
    for d in diags:
        d = dict(d)
        for k in ("stdout", "stderr", "output", "error"):
            if isinstance(d.get(k), str):
                d[k] = redact(d[k])
        out.append(d)
    return out
