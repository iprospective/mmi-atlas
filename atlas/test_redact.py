#!/usr/bin/env python3
"""test_redact — redaction LLM + résolution du registre de dispatch (RM2050).

Lancer : python3 test_redact.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact import redact, redact_diagnostics   # noqa: E402
from safe_dispatch import resolve                # noqa: E402

FAILED = False


def check(name, cond):
    global FAILED
    print(("  ✓ " if cond else "  ✗ ") + name)
    if not cond:
        FAILED = True


print("— Redaction —")
check("e-mail masqué", "[EMAIL]" in redact("contact: jean.dupont@client.fr ok"))
check("IPv4 masquée", redact("connexion depuis 57.130.41.131") == "connexion depuis [IP]")
check("port NON masqué (pas une IP)", "13306" in redact("listen 127.0.0.1:13306"))
check("version NON masquée", "MariaDB 10.6.23" in redact("MariaDB 10.6.23 server"))
check("password=val caviardé",
      "[CAVIARDÉ]" in redact("mysql --password=Sup3rS3cret -e x") and "Sup3rS3cret" not in redact("mysql --password=Sup3rS3cret -e x"))
check("token: val caviardé", "AKIA0000" not in redact("api_key: AKIA0000XXXX"))
check("url avec creds caviardée",
      "secret" not in redact("mysql://user:secret@db.lan/app") and "[CAVIARDÉ]@" in redact("mysql://user:secret@db.lan/app"))
key = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3Nz...\n-----END OPENSSH PRIVATE KEY-----"
check("bloc de clé privée masqué", redact(key) == "[CLÉ PRIVÉE]")
check("texte neutre inchangé", redact("mariadb.service active running") == "mariadb.service active running")

d = redact_diagnostics([{"op": "tail-log", "ok": True,
                         "stdout": "login admin@corp.com from 8.8.8.8 password=hunter2"}])
check("redact_diagnostics applique sur stdout",
      "[EMAIL]" in d[0]["stdout"] and "[IP]" in d[0]["stdout"] and "hunter2" not in d[0]["stdout"])

print("— Registre de dispatch (resolve) —")
r = resolve("bkp", registry={})
check("défaut interne : <node>.lan + clé par défaut",
      r["host"] == "bkp.lan" and r["host"].endswith(".lan") and r["proxyjump"] is None)
reg = {"defaults": {"user": "atlas-safe", "domain": "lan", "key": "/k/default"},
       "nodes": {"cli-web": {"endpoint": "192.0.2.40", "proxyjump": "cli-gw", "key": "/k/cli"}}}
r = resolve("cli-web", registry=reg)
check("nœud client : endpoint + proxyjump + clé dédiée",
      r["host"] == "192.0.2.40" and r["proxyjump"] == "cli-gw" and r["key"] == "/k/cli")
r = resolve("interne", registry=reg)
check("nœud absent → défaut (interne.lan + clé par défaut)",
      r["host"] == "interne.lan" and r["key"] == "/k/default")

print("ÉCHEC" if FAILED else "TOUS LES TESTS PASSENT")
sys.exit(1 if FAILED else 0)
