#!/usr/bin/env python3
"""atlas-bot — Bot Telegram « standardiste » d'Atlas (RM1812 / RM1814).

Coquille SÉCURISÉE du bot sysadmin Atlas : surface de communication + double
facteur d'authentification. À ce stade **aucune exécution privilégiée** — le
catalogue de scripts vetted (RM1816) se branchera sur le point d'extension
`dispatch_operation()` ci-dessous.

Le bot ne raisonne pas : il route Telegram ↔ opérations. Sécurité reprise de
`karl-telegram-bot` (RM1724/RM1777), durcie pour le périmètre sudo :

  1. **Whitelist** d'IDs Telegram (ATLAS_WHITELIST) — qui peut parler au bot.
  2. **Verrou applicatif TTL** (mot de passe) — protège même téléphone volé
     déverrouillé. Verrouillé par défaut, auto-lock court après inactivité,
     anti-brute-force. État en mémoire → fail-secure au redémarrage.

Commandes (toujours dispo) :
    /unlock <mdp>   déverrouille la session (le message est effacé après coup)
    /lock           verrouille immédiatement
    /help           aide
    /whoami         ton telegram_user_id (pour la whitelist)

Commandes (déverrouillé) :
    /status         état du bot (uptime, verrou)
    /ops            (placeholder) liste des opérations du catalogue — RM1816

Config (.env à côté de ce fichier, ou env shell) :
    ATLAS_BOT_TOKEN            token @BotFather (jamais loggué)
    ATLAS_WHITELIST           csv d'IDs autorisés (ex: "123456,789012")
    ATLAS_LOCK_PASSWORD_HASH  empreinte PBKDF2 du mdp (cf. --hash-password)

Outillage :
    python3 atlas-bot.py                  lance le bot
    python3 atlas-bot.py --hash-password  génère l'empreinte mdp
"""
import getpass
import hashlib
import hmac
import html
import os
import sys
import time
from datetime import timedelta
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from catalogue import Catalogue, ValidationError
from operations import OPERATIONS

TG_API = "https://api.telegram.org/bot{token}/{method}"

# Verrou plus strict que karl-pm (300 s) vu le périmètre sudo. Valeur affinée au
# durcissement (RM1818) ; surchargée par ATLAS_AUTO_LOCK_SECONDS si défini.
AUTO_LOCK_SECONDS = int(os.environ.get("ATLAS_AUTO_LOCK_SECONDS", "120"))
FAIL_THRESHOLD = 3        # nb d'échecs /unlock avant blocage
LOCKOUT_SECONDS = 300     # durée du blocage après FAIL_THRESHOLD échecs
PBKDF2_ITERATIONS = 200_000

VERSION = "v0.1"


# ─────────────────────────────── Mot de passe ───────────────────────────────

def hash_password(password):
    """Empreinte PBKDF2-SHA256 salée, format `pbkdf2_sha256$iters$salt$hash`."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    """Vérifie un mdp contre l'empreinte stockée (comparaison à temps constant)."""
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk, bytes.fromhex(hash_hex))
    except Exception:
        return False


# ──────────────────────────────── Verrouillage ──────────────────────────────

class Lock:
    """Gère l'état verrouillé/déverrouillé par chat + l'anti-brute-force.

    En mémoire uniquement → un redémarrage du bot re-verrouille tout (fail-secure).
    Désactivé (tout passe) si aucune empreinte n'est configurée — uniquement pour
    la phase de setup ; configure ATLAS_LOCK_PASSWORD_HASH pour activer.
    """

    def __init__(self, password_hash):
        self.hash = password_hash or None
        self._unlocked = {}   # chat_id -> dernier_activité_ts
        self._fails = {}      # chat_id -> {"count": int, "until": ts}

    @property
    def enabled(self):
        return self.hash is not None

    def is_unlocked(self, chat_id, now):
        if not self.enabled:
            return True
        last = self._unlocked.get(chat_id)
        if last is None:
            return False
        if now - last > AUTO_LOCK_SECONDS:
            self._unlocked.pop(chat_id, None)
            return False
        return True

    def touch(self, chat_id, now):
        """Rafraîchit le minuteur d'inactivité après une commande légitime."""
        if self.enabled and chat_id in self._unlocked:
            self._unlocked[chat_id] = now

    def lock(self, chat_id):
        self._unlocked.pop(chat_id, None)

    def attempt_unlock(self, chat_id, password, now):
        """Tente un déverrouillage. Retourne (statut, info) :
        ('ok', None) | ('lockout', secondes_restantes) |
        ('locked_now', LOCKOUT_SECONDS) | ('fail', essais_restants)."""
        f = self._fails.get(chat_id)
        if f and f["until"] > now:
            return ("lockout", int(f["until"] - now))
        if verify_password(password, self.hash):
            self._unlocked[chat_id] = now
            self._fails.pop(chat_id, None)
            return ("ok", None)
        count = (f["count"] if f else 0) + 1
        if count >= FAIL_THRESHOLD:
            self._fails[chat_id] = {"count": 0, "until": now + LOCKOUT_SECONDS}
            return ("locked_now", LOCKOUT_SECONDS)
        self._fails[chat_id] = {"count": count, "until": 0}
        return ("fail", FAIL_THRESHOLD - count)


# ───────────────────────────────── Telegram I/O ─────────────────────────────

def tg(token, method, **params):
    r = requests.post(TG_API.format(token=token, method=method), json=params, timeout=40)
    r.raise_for_status()
    return r.json()


def send(token, chat_id, text):
    tg(token, "sendMessage", chat_id=chat_id, text=text, parse_mode="HTML",
       disable_web_page_preview=True)


def delete_message(token, chat_id, message_id):
    """Best-effort : efface un message (scrub le mdp du /unlock de l'historique)."""
    try:
        tg(token, "deleteMessage", chat_id=chat_id, message_id=message_id)
    except Exception:
        pass


# ─────────────────────── Catalogue : liste & exécution ─────────────────────

def _trunc(s, n):
    s = s or ""
    return s if len(s) <= n else s[: n - 1] + "…"


def _safe(token, chat_id, fn):
    """Exécute fn() et envoie son résultat ; convertit les erreurs en message poli."""
    try:
        send(token, chat_id, fn())
    except Exception as e:
        send(token, chat_id, f"Erreur : {html.escape(str(e))}")


def cmd_ops(cat):
    """Liste les opérations du catalogue (id, description, palier d'autonomie)."""
    ops = cat.list()
    if not ops:
        return "Aucune opération dans le catalogue."
    lines = [f"• <code>{html.escape(o.id)}</code> — {html.escape(o.description)} "
             f"<i>[{o.autonomy}]</i>" for o in ops]
    return ("<b>Opérations disponibles</b> :\n" + "\n".join(lines)
            + "\n\nLancer : <code>/run &lt;op&gt; [args…]</code>")


def cmd_run(cat, actor, op_id, args):
    """Valide + exécute une opération du catalogue ; renvoie un message HTML."""
    try:
        res = cat.run(op_id, args, actor=actor)
    except ValidationError as e:
        return f"❌ {html.escape(str(e))}"
    head = "✅" if res.ok else f"⚠️ (exit {res.exit_code})"
    out = _trunc((res.stdout or res.stderr or "").rstrip(), 3500)
    body = f"\n<pre>{html.escape(out)}</pre>" if out else ""
    return f"{head} <b>{html.escape(op_id)}</b> — {res.duration_ms} ms{body}"


# ────────────────────────────────── Handler ─────────────────────────────────

HELP = ("<b>Atlas</b> — bot sysadmin sécurisé. Commandes :\n"
        "/status — état du bot\n"
        "/ops — liste des opérations du catalogue\n"
        "/run &lt;op&gt; [args…] — exécute une opération\n"
        "/lock — verrouiller\n"
        "/unlock &lt;mdp&gt; — déverrouiller\n"
        "/whoami — ton ID Telegram\n"
        "/help — cette aide")


def handle(bot, msg):
    token = bot["token"]
    lock = bot["lock"]
    chat_id = msg["chat"]["id"]
    msg_id = msg.get("message_id")
    user = msg.get("from") or {}
    uid = user.get("id")
    uname = user.get("username") or user.get("first_name") or "?"
    text = (msg.get("text") or "").strip()
    parts = text.split()
    cmd = parts[0].split("@")[0].lower() if parts else ""
    now = time.time()

    # /whoami : toujours dispo (sert à se whitelister)
    if cmd == "/whoami":
        send(token, chat_id, f"Ton telegram_user_id : <code>{uid}</code>\n"
                             f"chat_id : <code>{chat_id}</code>")
        return

    # Facteur 1 — whitelist
    wl = bot["whitelist"]
    if wl and uid not in wl:
        print(f"  ⨯ refus whitelist : uid={uid} (@{uname}) — text={text!r}")
        send(token, chat_id, "Désolé, tu n'es pas autorisé à parler à Atlas. "
                             "Demande à Mathieu de t'ajouter (ton ID : /whoami).")
        return
    if not wl:
        print(f"  ⚠ mode découverte : uid={uid} (@{uname}) — "
              f"ajoute-le à ATLAS_WHITELIST pour verrouiller")

    # Aide : dispo même verrouillé
    if cmd in ("/help", "/start"):
        send(token, chat_id, HELP)
        return

    # Facteur 2 — verrouillage
    if cmd == "/unlock":
        # On efface le message tout de suite : le mdp ne doit pas rester en clair.
        if msg_id:
            delete_message(token, chat_id, msg_id)
        if not lock.enabled:
            send(token, chat_id, "🔓 Verrouillage non configuré "
                                 "(ATLAS_LOCK_PASSWORD_HASH absent).")
            return
        password = text.split(None, 1)[1] if len(parts) > 1 else ""
        status, info = lock.attempt_unlock(chat_id, password, now)
        if status == "ok":
            print(f"  🔓 unlock OK : uid={uid}")
            send(token, chat_id, f"🔓 Déverrouillé. Auto-verrouillage dans "
                                 f"{AUTO_LOCK_SECONDS // 60} min "
                                 f"{AUTO_LOCK_SECONDS % 60} s d'inactivité. "
                                 f"/lock pour verrouiller maintenant.")
        elif status == "lockout":
            print(f"  ⛔ unlock pendant lockout : uid={uid} ({info}s restantes)")
            send(token, chat_id, f"⛔ Trop d'échecs. Réessaie dans {info // 60} min "
                                 f"{info % 60} s.")
        elif status == "locked_now":
            print(f"  ⛔ lockout déclenché : uid={uid}")
            send(token, chat_id, f"⛔ {FAIL_THRESHOLD} échecs — bloqué "
                                 f"{LOCKOUT_SECONDS // 60} min.")
        else:  # fail
            print(f"  ✗ unlock échec : uid={uid} ({info} essai(s) restant(s))")
            send(token, chat_id, f"❌ Mot de passe incorrect. "
                                 f"{info} essai(s) avant blocage.")
        return

    if cmd == "/lock":
        lock.lock(chat_id)
        send(token, chat_id, "🔒 Verrouillé.")
        return

    if not lock.is_unlocked(chat_id, now):
        send(token, chat_id, "🔒 Verrouillé. Déverrouille avec "
                             "<code>/unlock &lt;mot de passe&gt;</code>.")
        return

    # Session déverrouillée — on rafraîchit le minuteur d'inactivité
    lock.touch(chat_id, now)

    if cmd == "/status":
        up = timedelta(seconds=int(now - bot["start"]))
        verrou = "désactivé (setup)" if not lock.enabled else "actif 🔓 (session ouverte)"
        send(token, chat_id, f"✅ Atlas en ligne ({bot['version']}).\n"
                             f"• Uptime : {up}\n"
                             f"• Verrou : {verrou}\n"
                             f"• Auto-lock : {AUTO_LOCK_SECONDS} s\n"
                             f"• Catalogue : {len(bot['cat'].list())} opération(s)")
        return

    if cmd == "/ops":
        send(token, chat_id, cmd_ops(bot["cat"]))
        return

    if cmd == "/run":
        if len(parts) < 2:
            send(token, chat_id, "Usage : <code>/run &lt;op&gt; [args…]</code>. "
                                 "Liste : /ops")
            return
        actor = f"telegram:{uid}"
        _safe(token, chat_id, lambda: cmd_run(bot["cat"], actor, parts[1], parts[2:]))
        return

    send(token, chat_id, "Commande inconnue. /help pour la liste.")


# ─────────────────────────────────── Main ───────────────────────────────────

def load_dotenv():
    """Charge un .env situé à côté de ce script (clé=valeur), sans écraser l'env."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def gen_password_hash():
    """Mode --hash-password : prompt + impression de la ligne .env à coller."""
    p1 = getpass.getpass("Mot de passe de verrouillage Atlas : ")
    if len(p1) < 8:
        sys.exit("Trop court (8 caractères minimum pour un bot privilégié).")
    if p1 != getpass.getpass("Confirme : "):
        sys.exit("Les deux saisies diffèrent.")
    print("\nAjoute cette ligne dans .env (le mdp en clair n'est stocké nulle part) :\n")
    print(f"ATLAS_LOCK_PASSWORD_HASH={hash_password(p1)}")


def main():
    if "--hash-password" in sys.argv:
        gen_password_hash()
        return

    load_dotenv()
    token = os.environ.get("ATLAS_BOT_TOKEN")
    if not token:
        sys.exit("ERREUR : ATLAS_BOT_TOKEN absent (.env ou env). "
                 "Crée le bot via @BotFather puis ajoute la ligne dans .env.")
    wl_raw = os.environ.get("ATLAS_WHITELIST", "")
    whitelist = {int(x) for x in wl_raw.replace(" ", "").split(",") if x.strip().isdigit()}
    lock = Lock(os.environ.get("ATLAS_LOCK_PASSWORD_HASH"))
    cat = Catalogue(OPERATIONS)

    bot = {"token": token, "whitelist": whitelist, "lock": lock, "cat": cat,
           "start": time.time(), "version": VERSION}

    me = tg(token, "getMe")["result"]
    print(f"✓ Atlas connecté : @{me.get('username')} ({me.get('first_name')})")
    print(f"  Whitelist : {whitelist or 'VIDE (mode découverte)'}")
    if lock.enabled:
        print(f"  Verrou : ACTIF (auto-lock {AUTO_LOCK_SECONDS} s, "
              f"lockout {FAIL_THRESHOLD} échecs / {LOCKOUT_SECONDS // 60} min)")
    else:
        print("  Verrou : DÉSACTIVÉ — configure ATLAS_LOCK_PASSWORD_HASH "
              "(python3 atlas-bot.py --hash-password)")
    print(f"  Catalogue : {len(cat.list())} opération(s) — {', '.join(o.id for o in cat.list())}")
    print("  Long-polling… (Ctrl-C pour arrêter)")

    offset = None
    while True:
        try:
            resp = tg(token, "getUpdates", offset=offset, timeout=30)
        except requests.RequestException as e:
            print(f"  ⚠ getUpdates erreur réseau : {e} — retry dans 3s")
            time.sleep(3)
            continue
        for upd in resp.get("result", []):
            offset = upd["update_id"] + 1
            msg = upd.get("message") or upd.get("edited_message")
            if not msg or "text" not in msg:
                continue
            # On ne logge que la 1re token (la commande) : évite de fuiter un mdp /unlock.
            first_tok = (msg["text"].split() or [""])[0]
            print(f"  → update {upd['update_id']} : {first_tok!r}")
            try:
                handle(bot, msg)
            except Exception as e:
                print(f"  ⚠ handler erreur : {e}")


if __name__ == "__main__":
    main()
