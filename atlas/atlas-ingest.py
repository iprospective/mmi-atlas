#!/usr/bin/env python3
"""atlas-ingest — endpoint d'ingestion des événements de monitoring (RM1813).

Interface **non privilégiée** (membre de `atlas-ifaces`, NoNewPrivileges) qui
reçoit les webhooks de monitoring (Zabbix d'abord), les **authentifie** (HMAC
SHA-256 sur le corps brut + secret partagé), normalise le payload, et le **relaie
au cœur** (`submit_event`). Le cœur seul décide + exécute (politique + garde-fous).

Aucune exécution ni privilège ici : c'est un **relais signé**. À binder sur le
réseau privé (vrack), jamais exposé sur l'IP publique.

  POST /ingest   — header `X-Atlas-Signature: sha256=<hex>` ; corps = JSON Zabbix.
  GET  /health   — liveness (sans auth).

Conf via env :
  ATLAS_INGEST_SECRET   secret HMAC partagé avec le webhook Zabbix (obligatoire)
  ATLAS_INGEST_BIND     IP d'écoute (défaut 127.0.0.1 ; en prod = IP vrack)
  ATLAS_INGEST_PORT     port (défaut 8088)
  ATLAS_SOCKET          socket du cœur (hérité par atlas_client)
"""
import hashlib
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from atlas_client import submit_event, CoreUnavailable  # noqa: E402

SECRET = os.environ.get("ATLAS_INGEST_SECRET", "").encode("utf-8")
BIND = os.environ.get("ATLAS_INGEST_BIND", "127.0.0.1")
PORT = int(os.environ.get("ATLAS_INGEST_PORT", "8088"))
MAX_BODY = 64 * 1024


def verify_sig(body: bytes, header: str) -> bool:
    """HMAC-SHA256 du corps brut == signature fournie (comparaison constante)."""
    if not SECRET or not header:
        return False
    expected = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.strip())


def normalize(payload: dict) -> dict:
    """Payload webhook → événement normalisé pour le cœur (champs sûrs, str)."""
    g = lambda *keys: next((str(payload[k]) for k in keys if payload.get(k) not in (None, "")), "")
    return {
        "source": "zabbix",
        "host": g("host", "hostname", "host_name"),
        "trigger": g("trigger", "trigger_name", "name"),
        "severity": g("severity", "nseverity").lower() or "average",
        "state": (g("state", "status", "value") or "PROBLEM").upper(),
        "event_id": g("event_id", "eventid", "id"),
        "item": g("item", "item_key", "key"),
        "value": g("value", "item_value"),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "atlas-ingest/1.0"

    def _json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # journal compact sur stderr
        sys.stderr.write("ingest %s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"ok": True, "service": "atlas-ingest"})
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path != "/ingest":
            return self._json(404, {"ok": False, "error": "not found"})
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > MAX_BODY:
            return self._json(400, {"ok": False, "error": "corps absent ou trop volumineux"})
        body = self.rfile.read(length)
        if not verify_sig(body, self.headers.get("X-Atlas-Signature", "")):
            return self._json(401, {"ok": False, "error": "signature invalide"})
        try:
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise ValueError("objet JSON attendu")
        except ValueError as e:
            return self._json(400, {"ok": False, "error": f"JSON invalide : {e}"})

        event = normalize(payload)
        if not event["host"] or not event["trigger"]:
            return self._json(400, {"ok": False, "error": "host/trigger manquant"})
        actor = f"zabbix:{event['host']}"
        try:
            resp = submit_event(event, actor=actor)
        except CoreUnavailable as e:
            return self._json(503, {"ok": False, "error": str(e)})
        self._json(200, resp)


def main():
    if not SECRET:
        print("atlas-ingest: ATLAS_INGEST_SECRET non défini — refus de démarrer", file=sys.stderr)
        sys.exit(2)
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"atlas-ingest: écoute http://{BIND}:{PORT} (POST /ingest, GET /health)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
