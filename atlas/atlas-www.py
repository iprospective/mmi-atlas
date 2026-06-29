#!/usr/bin/env python3
"""atlas-www — interface web sysadmin d'Atlas (RM2040 / épic RM1812).

Seconde **interface distante** d'Atlas, sœur de `atlas-bot` : une UI web pour
déclencher les opérations du catalogue et lancer des diagnostics read-only.
**Zéro privilège** — exactement comme le bot : elle ne valide ni n'exécute, elle
*relaie* une intention au CŒUR via le socket local (RM2039) qui, lui, ré-authentifie
(catalogue + paliers d'autonomie), exécute et audite. Cf. docs/atlas-architecture.md.

Surface réduite, stdlib uniquement (http.server + ssl) — pas de dépendance ni de
framework web. Servie **par le conteneur `atlas`**, TLS + auth **in-container**, sans
proxy.

Modèle de sécurité (la surface exposée ne doit JAMAIS pouvoir escalader) :
  1. **TLS** — cert/clé in-container (auto-signé déposé au déploiement). Bind
     **loopback par défaut** (`ATLAS_WWW_BIND`) : exposer = choix explicite.
  2. **Auth HTTP Basic** sur TLS — un seul compte, mot de passe vérifié contre une
     empreinte PBKDF2-SHA256 (jamais le mdp en clair). Comparaison à temps constant.
  3. **Anti-brute-force** — lockout par IP cliente après N échecs (fail-secure :
     état en mémoire, réinitialisé au redémarrage).
  4. **CSRF** — double barrière sur les requêtes mutantes (POST) : contrôle
     `Origin`/`Referer` same-origin + jeton HMAC embarqué dans les formulaires.
  5. **Zéro pouvoir direct** — ni sudo, ni clé SSH, ni filesystem du cœur : tout
     passe par le socket. Un compromis de cette interface = au pire soumettre une
     intention filtrée (le cœur reste seul juge).

Config (.env à côté de ce fichier, ou env shell — fichier 0640 root:atlas-www) :
    ATLAS_WWW_USER            identifiant du compte web (défaut: atlas)
    ATLAS_WWW_PASSWORD_HASH   empreinte PBKDF2 du mdp (cf. --hash-password) — REQUIS
    ATLAS_WWW_BIND            adresse d'écoute (défaut: 127.0.0.1 ; 0.0.0.0 = exposé)
    ATLAS_WWW_PORT            port HTTPS (défaut: 8443)
    ATLAS_WWW_CERT            chemin cert TLS PEM (défaut: /opt/atlas/tls/www.crt)
    ATLAS_WWW_KEY             chemin clé TLS PEM (défaut: /opt/atlas/tls/www.key)
    ATLAS_WWW_SECRET          secret HMAC CSRF (défaut: aléatoire par process)
    ATLAS_SOCKET              socket du cœur (défaut: /run/atlas/atlas.sock)

Outillage :
    python3 atlas-www.py                  lance le serveur
    python3 atlas-www.py --hash-password  génère l'empreinte mdp (ligne .env)
"""
import base64
import getpass
import hashlib
import hmac
import html
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalogue import Catalogue                      # métadonnées du catalogue (listing) uniquement
from operations import OPERATIONS
from atlas_client import (submit, submit_diag, submit_status,  # socket du cœur (RM2039)
                          CoreUnavailable)

VERSION = "v0.1"
PBKDF2_ITERATIONS = 200_000      # identique au verrou du bot (RM1814)
FAIL_THRESHOLD = 5               # échecs d'auth avant lockout (par IP)
LOCKOUT_SECONDS = 300            # durée du blocage


# ─────────────────────────── Mot de passe (PBKDF2) ──────────────────────────
# Même schéma que le verrou applicatif du bot (atlas-bot.py) : `pbkdf2_sha256$…`.
# Dupliqué volontairement (chaque interface est autonome ; aucune dépendance croisée).

def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk, bytes.fromhex(hash_hex))
    except Exception:
        return False


# ─────────────────────────── Anti-brute-force (IP) ──────────────────────────

class IPGuard:
    """Lockout par IP cliente après FAIL_THRESHOLD échecs d'auth. Thread-safe."""

    def __init__(self):
        self._fails = {}          # ip -> {"count": int, "until": ts}
        self._lock = threading.Lock()

    def blocked_for(self, ip, now):
        with self._lock:
            f = self._fails.get(ip)
            return int(f["until"] - now) if f and f["until"] > now else 0

    def record_fail(self, ip, now):
        with self._lock:
            f = self._fails.get(ip) or {"count": 0, "until": 0}
            f["count"] += 1
            if f["count"] >= FAIL_THRESHOLD:
                f = {"count": 0, "until": now + LOCKOUT_SECONDS}
            self._fails[ip] = f

    def record_ok(self, ip):
        with self._lock:
            self._fails.pop(ip, None)


# ───────────────────────────── Rendu HTML ───────────────────────────────────

_CEIL_LABEL = {"observe": "observe (diagnostic seul)",
               "approve": "approve (approbation humaine)",
               "execute": "execute (auto-remédiation)"}

CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#15181c;color:#dfe3e8}
header{background:#1d2228;padding:14px 22px;border-bottom:1px solid #2c333b;
 display:flex;align-items:center;gap:12px}
header b{font-size:17px}
header .v{color:#7d8794;font-size:12px}
main{max-width:880px;margin:0 auto;padding:22px}
h2{font-size:15px;margin:26px 0 10px;color:#9fb3c8;border-bottom:1px solid #2c333b;padding-bottom:6px}
.card{background:#1d2228;border:1px solid #2c333b;border-radius:8px;padding:14px 16px;margin:10px 0}
.kv{display:flex;gap:8px;flex-wrap:wrap}
.kv span{background:#262d35;border-radius:5px;padding:3px 9px;font-size:13px}
form.op{display:flex;flex-wrap:wrap;align-items:end;gap:8px;margin:0}
form.op .o{font-weight:600}
form.op .d{color:#8b94a0;flex:1 1 180px;min-width:120px}
label{display:flex;flex-direction:column;font-size:12px;color:#8b94a0;gap:2px}
input,select{background:#11141a;color:#dfe3e8;border:1px solid #39424c;border-radius:5px;
 padding:6px 8px;font:13px system-ui}
button{background:#2563b0;color:#fff;border:0;border-radius:5px;padding:7px 14px;
 cursor:pointer;font:13px system-ui}
button:hover{background:#2d72c9}
button.danger{background:#a23636}button.danger:hover{background:#bd4040}
.tier{font-size:11px;padding:1px 7px;border-radius:9px;background:#2a3038;color:#9aa4af}
.tier.P2{background:#5a2a2a;color:#f0c0c0}.tier.P1{background:#3d4a2a;color:#d3e0b0}
.tier.P0{background:#2a3a4a;color:#bcd6ef}
pre{background:#0e1116;border:1px solid #2c333b;border-radius:6px;padding:11px;
 overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px ui-monospace,monospace}
.ok{color:#7fce7f}.warn{color:#e6b35a}.err{color:#e87f7f}
.note{color:#7d8794;font-size:12px}
a{color:#6aa6e8}
"""


def page(body, *, user="?"):
    return ("<!doctype html><html lang=fr><head><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Atlas — console sysadmin</title><style>{CSS}</style></head><body>"
            f"<header><b>🛰 Atlas</b> <span class=v>console sysadmin {VERSION}</span>"
            f"<span style='margin-left:auto' class=v>connecté : {html.escape(user)} · "
            f"<a href='/'>rafraîchir</a></span></header><main>{body}</main></body></html>")


def status_card():
    try:
        st = submit_status(actor="atlas-www")
    except CoreUnavailable as e:
        return f"<div class=card><span class=err>⚠️ cœur injoignable</span> — {html.escape(str(e))}</div>"
    ceil = _CEIL_LABEL.get(st.get("ceiling"), st.get("ceiling"))
    return ("<div class=card><div class=kv>"
            f"<span>cœur : <b class=ok>en ligne</b></span>"
            f"<span>autonomie : <b>{html.escape(str(ceil))}</b></span>"
            f"<span>diagnostic auto : {'on' if st.get('diagnose') else 'off'}</span>"
            f"<span>règles : {html.escape(str(st.get('rules')))}</span>"
            f"<span>approbations en attente : {html.escape(str(st.get('pending')))}</span>"
            "</div></div>")


def _arg_input(spec):
    """Champ de formulaire pour un ArgSpec (select pour choice, number pour int)."""
    req = " required" if spec.required else ""
    star = " *" if spec.required else ""
    lbl = html.escape(spec.name) + star
    if spec.kind == "choice":
        opts = "" if spec.required else "<option value=''>—</option>"
        opts += "".join(f"<option>{html.escape(str(c))}</option>" for c in spec.choices)
        field = f"<select name=arg{req}>{opts}</select>"
    elif spec.kind == "int":
        mn = f" min={spec.min}" if spec.min is not None else ""
        mx = f" max={spec.max}" if spec.max is not None else ""
        field = f"<input type=number name=arg{mn}{mx}{req}>"
    else:  # token
        field = f"<input type=text name=arg autocomplete=off{req}>"
    return f"<label>{lbl}{field}</label>"


def ops_section(cat, csrf):
    rows = []
    for o in cat.list():
        inputs = "".join(_arg_input(a) for a in o.args)
        disruptive = (o.autonomy in ("P2",)) or o.needs_sudo
        btn_cls = " class=danger" if disruptive else ""
        confirm = (" onsubmit=\"return confirm('Action potentiellement disruptive : "
                   f"{html.escape(o.id)}. Confirmer ?')\"" if disruptive else "")
        rows.append(
            f"<div class=card><form class=op method=post action=/run{confirm}>"
            f"<input type=hidden name=csrf value='{csrf}'>"
            f"<input type=hidden name=op value='{html.escape(o.id)}'>"
            f"<span class=o>{html.escape(o.id)}</span>"
            f"<span class='tier {o.autonomy}'>{o.autonomy}</span>"
            f"<span class=d>{html.escape(o.description)}</span>"
            f"{inputs}<button{btn_cls}>exécuter</button></form></div>")
    return "<h2>Opérations du catalogue</h2>" + "".join(rows)


def diag_section(csrf):
    return ("<h2>Diagnostic read-only (on-target)</h2>"
            "<div class=card><form class=op method=post action=/diag>"
            f"<input type=hidden name=csrf value='{csrf}'>"
            "<label>nœud *<input type=text name=node autocomplete=off required "
            "placeholder='ex: mmi, node3, client-mail'></label>"
            "<label>op<input type=text name=op autocomplete=off "
            "placeholder='(vide = liste les ops)'></label>"
            "<label>args<input type=text name=args autocomplete=off "
            "placeholder='ex: syslog 40'></label>"
            "<button>diagnostiquer</button></form>"
            "<p class=note>Plan léger read-only via <code>atlas-safe@&lt;nœud&gt;</code> "
            "(flotte + clients). Ne modifie rien.</p></div>")


def result_card(title, resp):
    """Carte de résultat commune (run/diag) à partir de la réponse du cœur."""
    if resp.get("error"):
        return f"<div class=card><span class=err>❌ {html.escape(resp['error'])}</span></div>"
    if "ops" in resp and not resp.get("_op"):
        ops = ", ".join(resp.get("ops") or [])
        return (f"<div class=card><b>{html.escape(title)}</b> — ops read-only :"
                f"<pre>{html.escape(ops)}</pre></div>")
    ok = resp.get("ok")
    head = "<span class=ok>✅ succès</span>" if ok else f"<span class=warn>⚠️ exit {resp.get('exit')}</span>"
    out = (resp.get("stdout") or resp.get("stderr") or "").rstrip()
    body = f"<pre>{html.escape(out)}</pre>" if out else "<p class=note>(aucune sortie)</p>"
    dur = resp.get("duration_ms", "?")
    return f"<div class=card><b>{html.escape(title)}</b> — {head} · {dur} ms{body}</div>"


# ─────────────────────────────── Handler HTTP ───────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "atlas-www"
    protocol_version = "HTTP/1.1"

    # — utilitaires —
    def _client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    def log_message(self, fmt, *args):
        # Log minimal sans en-tête : ne jamais fuiter l'Authorization.
        print(f"  {self._client_ip()} {fmt % args}")

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _unauthorized(self):
        self._send(401, page("<div class=card><span class=err>🔒 Authentification requise.</span></div>"),
                   extra={"WWW-Authenticate": 'Basic realm="Atlas", charset="UTF-8"'})

    def _authenticate(self):
        """HTTP Basic sur TLS + anti-brute-force. Retourne le user ou None (401 envoyé)."""
        cfg = self.server.atlas
        now = time.time()
        ip = self._client_ip()
        wait = cfg["guard"].blocked_for(ip, now)
        if wait:
            self._send(429, page(f"<div class=card><span class=err>⛔ Trop d'échecs — "
                                 f"réessaie dans {wait // 60} min {wait % 60} s.</span></div>"))
            return None
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                raw = base64.b64decode(hdr[6:]).decode("utf-8", "replace")
                u, _, p = raw.partition(":")
            except Exception:
                u, p = "", ""
            user_ok = hmac.compare_digest(u, cfg["user"])
            pass_ok = verify_password(p, cfg["pw_hash"])
            if user_ok and pass_ok:
                cfg["guard"].record_ok(ip)
                return cfg["user"]
            cfg["guard"].record_fail(ip, now)
            print(f"  ⨯ auth échec : ip={ip} user={u!r}")
        self._unauthorized()
        return None

    def _csrf_ok(self, form):
        """Double barrière CSRF : same-origin (Origin/Referer) + jeton HMAC."""
        cfg = self.server.atlas
        # 1) same-origin : l'Origin/Referer doit pointer sur notre propre Host.
        host = (self.headers.get("Host") or "").strip()
        origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if origin:
            netloc = urlsplit(origin).netloc
            if host and netloc and netloc != host:
                return False
        # 2) jeton HMAC stable par process, embarqué dans les formulaires.
        tok = (form.get("csrf") or [""])[0]
        return hmac.compare_digest(tok, cfg["csrf"])

    def _read_form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return parse_qs(raw, keep_blank_values=True)

    # — routes —
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        user = self._authenticate()
        if not user:
            return
        cfg = self.server.atlas
        path = urlsplit(self.path).path
        if path == "/":
            body = (status_card()
                    + ops_section(cfg["cat"], cfg["csrf"])
                    + diag_section(cfg["csrf"]))
            self._send(200, page(body, user=user))
        else:
            self._send(404, page("<div class=card>Page inconnue. <a href='/'>Accueil</a></div>", user=user))

    def do_POST(self):
        user = self._authenticate()
        if not user:
            return
        cfg = self.server.atlas
        path = urlsplit(self.path).path
        form = self._read_form()
        if not self._csrf_ok(form):
            self._send(403, page("<div class=card><span class=err>⚠️ Requête rejetée "
                                 "(CSRF / origine invalide). <a href='/'>Retour</a></span></div>", user=user))
            return
        actor = f"www:{user}"
        if path == "/run":
            self._handle_run(form, actor, user)
        elif path == "/diag":
            self._handle_diag(form, actor, user)
        else:
            self._send(404, page("<div class=card>Action inconnue.</div>", user=user))

    def _handle_run(self, form, actor, user):
        op = (form.get("op") or [""])[0]
        args = [a for a in form.get("arg", []) if a != ""]
        if not op:
            self._send(400, page("<div class=card><span class=err>Opération manquante.</span></div>", user=user))
            return
        try:
            resp = submit(op, args, actor=actor)
        except CoreUnavailable as e:
            resp = {"error": f"cœur Atlas injoignable — {e}"}
        title = f"{op} {' '.join(args)}".strip()
        self._send(200, page(result_card(title, resp)
                             + "<p class=note><a href='/'>← retour à la console</a></p>", user=user))

    def _handle_diag(self, form, actor, user):
        node = (form.get("node") or [""])[0].strip()
        op = (form.get("op") or [""])[0].strip()
        args = (form.get("args") or [""])[0].split()
        if not node:
            self._send(400, page("<div class=card><span class=err>Nœud manquant.</span></div>", user=user))
            return
        try:
            resp = submit_diag(node, op, args, actor=actor)
            resp["_op"] = op    # indice de rendu : op vide → listing
        except CoreUnavailable as e:
            resp = {"error": f"cœur Atlas injoignable — {e}"}
        title = f"{node} · {op or '(liste)'}"
        self._send(200, page(result_card(title, resp)
                             + "<p class=note><a href='/'>← retour à la console</a></p>", user=user))


# ─────────────────────────────────── Main ───────────────────────────────────

def load_dotenv():
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def gen_password_hash():
    p1 = getpass.getpass("Mot de passe de la console web Atlas : ")
    if len(p1) < 10:
        sys.exit("Trop court (10 caractères minimum pour une console privilégiée).")
    if p1 != getpass.getpass("Confirme : "):
        sys.exit("Les deux saisies diffèrent.")
    print("\nAjoute cette ligne dans .env (le mdp en clair n'est stocké nulle part) :\n")
    print(f"ATLAS_WWW_PASSWORD_HASH={hash_password(p1)}")


def main():
    if "--hash-password" in sys.argv:
        gen_password_hash()
        return

    load_dotenv()
    pw_hash = os.environ.get("ATLAS_WWW_PASSWORD_HASH")
    if not pw_hash:
        sys.exit("ERREUR : ATLAS_WWW_PASSWORD_HASH absent (.env ou env). "
                 "Génère-le : python3 atlas-www.py --hash-password — "
                 "une console web sans auth ne démarre pas (fail-secure).")
    user = os.environ.get("ATLAS_WWW_USER", "atlas")
    bind = os.environ.get("ATLAS_WWW_BIND", "127.0.0.1")
    port = int(os.environ.get("ATLAS_WWW_PORT", "8443"))
    cert = os.environ.get("ATLAS_WWW_CERT", "/opt/atlas/tls/www.crt")
    key = os.environ.get("ATLAS_WWW_KEY", "/opt/atlas/tls/www.key")
    secret = os.environ.get("ATLAS_WWW_SECRET") or os.urandom(32).hex()
    if not (Path(cert).exists() and Path(key).exists()):
        sys.exit(f"ERREUR : cert/clé TLS introuvables ({cert} / {key}). "
                 "Le déploiement (deploy-www.sh) en génère un auto-signé.")

    cat = Catalogue(OPERATIONS)
    csrf = hmac.new(secret.encode(), b"atlas-www-csrf", hashlib.sha256).hexdigest()

    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.atlas = {"user": user, "pw_hash": pw_hash, "cat": cat,
                   "csrf": csrf, "guard": IPGuard()}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    exposed = bind not in ("127.0.0.1", "::1", "localhost")
    print(f"✓ Atlas-www {VERSION} — https://{bind}:{port}/ (user: {user})")
    print(f"  Catalogue : {len(cat.list())} opération(s) — {', '.join(o.id for o in cat.list())}")
    print(f"  Bind : {bind} {'⚠️ EXPOSÉ (hors loopback)' if exposed else '(loopback — sûr)'}")
    print(f"  Anti-brute-force : {FAIL_THRESHOLD} échecs / lockout {LOCKOUT_SECONDS // 60} min")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  arrêt.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
