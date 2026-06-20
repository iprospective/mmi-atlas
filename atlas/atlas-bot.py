#!/usr/bin/env python3
"""atlas-bot — Bot Telegram « standardiste » d'Atlas (RM1812 / RM1814).

Coquille SÉCURISÉE du bot sysadmin Atlas : surface de communication + double
facteur d'authentification. **Zéro privilège** : le bot ne valide ni n'exécute —
il *relaie* au cœur via le socket (RM2039) qui, lui, valide (catalogue) + exécute.

Deux sens de trafic :
  - **humain → cœur** : commandes `/run` relayées au cœur (RM2039) ;
  - **cœur → humain** : le bot *tire* les notifications du moteur de décision
    (RM1813) — alertes, escalades, et **approbations P2** postées avec boutons
    inline ; un tap « ✅ » appelle `resolve` (exige une session déverrouillée).

Le bot ne raisonne pas : il route Telegram ↔ cœur. Sécurité reprise de
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
from catalogue import Catalogue, ValidationError  # métadonnées du catalogue (listing) uniquement
from operations import OPERATIONS
from atlas_client import (submit, submit_resolve, submit_poll,  # socket du cœur (RM2039/RM1813)
                          submit_status, CoreUnavailable)

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


def send_kbd(token, chat_id, text, keyboard):
    tg(token, "sendMessage", chat_id=chat_id, text=text, parse_mode="HTML",
       disable_web_page_preview=True, reply_markup={"inline_keyboard": keyboard})


def edit_text(token, chat_id, message_id, text):
    try:
        tg(token, "editMessageText", chat_id=chat_id, message_id=message_id,
           text=text, parse_mode="HTML")
    except Exception:
        pass


def answer_callback(token, cb_id, text=""):
    try:
        tg(token, "answerCallbackQuery", callback_query_id=cb_id, text=text)
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


def cmd_run(actor, op_id, args):
    """Soumet l'op au CŒUR Atlas via le socket (RM2039) ; renvoie un message HTML.

    Le bot ne valide ni n'exécute plus lui-même (zéro privilège) : il **relaie**
    l'intention au cœur, qui valide (catalogue), exécute (sudo local ou dispatch
    SSH RM1813) et audite."""
    try:
        resp = submit(op_id, args, actor=actor)
    except CoreUnavailable as e:
        return f"❌ cœur Atlas injoignable — {html.escape(str(e))}"
    if resp.get("error"):
        return f"❌ {html.escape(resp['error'])}"
    head = "✅" if resp.get("ok") else f"⚠️ (exit {resp.get('exit')})"
    out = _trunc((resp.get("stdout") or resp.get("stderr") or "").rstrip(), 3500)
    body = f"\n<pre>{html.escape(out)}</pre>" if out else ""
    return f"{head} <b>{html.escape(op_id)}</b> — {resp.get('duration_ms', '?')} ms{body}"


# ──────────────────── Notifications du cœur → Telegram (RM1813) ─────────────

_ACTION_ICON = {"execute": "🔧", "approve": "❓", "escalate": "🚨", "notify": "🔔"}
_SEV_ICON = {"disaster": "🟥", "high": "🟧", "average": "🟨",
             "warning": "🟦", "information": "⬜", "not_classified": "⬜"}


def _diag_block(n):
    """Bloc « diagnostic » (ops read-only) à joindre à l'alerte, si présent."""
    diag = n.get("diagnosis") or []
    if not diag:
        return ""
    lines = []
    for d in diag:
        mark = "" if d.get("ok") else "⚠️ "
        out = _trunc((d.get("output") or "").strip(), 600)
        lines.append(f"<b>{mark}{html.escape(d.get('op') or '?')}</b>\n"
                     f"<pre>{html.escape(out)}</pre>")
    return "\n🔎 <b>Diagnostic</b>\n" + "\n".join(lines)


def _held_note(n):
    """Note quand le plafond d'autonomie a retenu une action."""
    if not n.get("held"):
        return ""
    proposed = {"execute": "auto-remédiation", "approve": "approbation"}.get(
        n.get("proposed"), n.get("proposed") or "action")
    op = html.escape(n.get("op") or "?")
    args = html.escape(" ".join(n.get("args") or []))
    return (f"\n🛡️ <i>Plafond d'autonomie : {proposed} <code>{op} {args}</code> "
            f"proposée mais NON exécutée — diagnostic seul.</i>")


def format_notif(n):
    """(texte HTML, clavier|None) pour une notification du cœur."""
    # Rappel opérationnel (ex. clés à recharger, RM2058) — texte déjà formaté (HTML).
    if n.get("action") == "reminder":
        return n.get("text") or "", None

    # Diagnostic IA on-target (RM2050) — message dédié, sans clavier.
    if n.get("action") == "ai-diagnosis":
        host = html.escape(n.get("host") or "?")
        trig = html.escape(n.get("trigger") or "")
        text = html.escape(_trunc(n.get("text") or "", 3500))
        return f"🧠 <b>Diagnostic IA — {host}</b>\n<i>{trig}</i>\n\n{text}", None

    state = (n.get("state") or "").upper()
    icon = "✅" if state == "OK" else _ACTION_ICON.get(n.get("action"), "🔔")
    sev = _SEV_ICON.get((n.get("severity") or "").lower(), "")
    host = html.escape(n.get("host") or "?")
    trig = html.escape(n.get("trigger") or "?")
    reason = html.escape(n.get("reason") or "")
    head = f"{icon} <b>{host}</b> — {trig}"
    meta = f"\n<i>{reason}</i>\n[{n.get('tier')} · {sev}{html.escape(n.get('severity') or '')} · {state}]"
    diag = _diag_block(n)

    # approve réel (token présent) → boutons. Si le plafond a retenu l'action,
    # il n'y a pas de token → on tombe sur l'alerte enrichie + note de plafond.
    if n.get("action") == "approve" and n.get("token"):
        op = html.escape(n.get("op") or "?")
        args = html.escape(" ".join(n.get("args") or []))
        tok = n["token"]
        txt = (f"{head}\n❓ <b>Approbation requise</b> — action proposée :\n"
               f"<code>{op} {args}</code>{meta}{diag}")
        kbd = [[{"text": "✅ Approuver", "callback_data": f"a:ok:{tok}"},
                {"text": "✖️ Refuser", "callback_data": f"a:no:{tok}"}]]
        return txt, kbd

    if n.get("action") == "execute":
        ex = n.get("exit")
        verdict = "réussie ✅" if n.get("ok") else f"échouée ⚠️ (exit {ex})"
        op = html.escape(n.get("op") or "?")
        return f"{head}\n🔧 Auto-remédiation P1 <code>{op}</code> {verdict}.{meta}{diag}", None

    if n.get("action") == "escalate":
        return (f"{head}\n🚨 <b>Escalade</b> — garde-fou déclenché, action automatique "
                f"stoppée.{meta}{_held_note(n)}{diag}"), None

    # notify (y compris action retenue par le plafond) → alerte + diagnostic
    return f"{head}{meta}{_held_note(n)}{diag}", None


def poll_and_notify(bot):
    """Tire les notifications du cœur et les poste aux chats d'alerte."""
    try:
        resp = submit_poll(actor="atlas-bot")
    except CoreUnavailable:
        return  # cœur down : on réessaiera au prochain tour (alertes best-effort)
    for n in resp.get("notifs", []):
        text, kbd = format_notif(n)
        for chat_id in bot["alert_chats"]:
            try:
                if kbd:
                    send_kbd(bot["token"], chat_id, text, kbd)
                else:
                    send(bot["token"], chat_id, text)
            except Exception as e:
                print(f"  ⚠ notif → chat {chat_id} échec : {e}")


def handle_callback(bot, cb):
    """Tap sur un bouton inline — résout une approbation P2 (RM1813)."""
    token = bot["token"]
    lock = bot["lock"]
    cb_id = cb["id"]
    data = cb.get("data") or ""
    user = cb.get("from") or {}
    uid = user.get("id")
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")
    msg_id = msg.get("message_id")
    now = time.time()

    wl = bot["whitelist"]
    if wl and uid not in wl:
        return answer_callback(token, cb_id, "Non autorisé.")
    # Une approbation EXÉCUTE une op privilégiée → exige une session déverrouillée.
    if not lock.is_unlocked(chat_id, now):
        return answer_callback(token, cb_id, "🔒 Verrouillé — /unlock d'abord, puis re-tape.")
    lock.touch(chat_id, now)

    parts = data.split(":")
    if len(parts) != 3 or parts[0] != "a":
        return answer_callback(token, cb_id, "Action inconnue.")
    approved = parts[1] == "ok"
    tok = parts[2]
    try:
        resp = submit_resolve(tok, approved, actor=f"telegram:{uid}")
    except CoreUnavailable as e:
        return answer_callback(token, cb_id, f"Cœur injoignable : {e}")

    if not resp.get("ok"):
        answer_callback(token, cb_id, resp.get("error", "Échec."))
        if msg_id:
            edit_text(token, chat_id, msg_id, "⏱️ <i>Approbation périmée ou déjà traitée.</i>")
        return
    if resp.get("action") == "denied":
        answer_callback(token, cb_id, "Refusé.")
        edit_text(token, chat_id, msg_id, "✖️ <b>Action refusée.</b> Aucune exécution.")
        return
    # executed
    r = resp.get("result", {})
    verdict = "réussie ✅" if r.get("ok") else f"échouée ⚠️ (exit {r.get('exit')})"
    op = html.escape(resp.get("op") or "?")
    answer_callback(token, cb_id, "Approuvé — exécution lancée.")
    edit_text(token, chat_id, msg_id,
              f"✅ <b>Approuvé</b> par @{html.escape(user.get('username') or str(uid))} — "
              f"<code>{op}</code> {verdict}.")


# ────────────────────────────────── Handler ─────────────────────────────────

HELP = ("<b>Atlas</b> — bot sysadmin sécurisé. Commandes :\n"
        "/status — état du bot\n"
        "/ops — liste des opérations du catalogue\n"
        "/run &lt;op&gt; [args…] — exécute une opération\n"
        "(les alertes &amp; approbations du monitoring arrivent automatiquement ; "
        "approuver = tap ✅ sur le bouton, session déverrouillée)\n"
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

    # Les chats d'alerte (groupe Zabbix) sont OUTBOUND only : Atlas y POSTE les
    # diagnostics du monitoring mais n'y RÉPOND PAS aux commandes (exigence : ce canal
    # ne sert qu'aux alertes Zabbix, pas aux autres demandes). RM1813.
    if chat_id in bot.get("alert_chats", set()):
        return

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
        # Plafond d'autonomie + compteurs : interrogés au cœur.
        ceil_line = ""
        try:
            st = submit_status(actor="atlas-bot")
            _CEIL_LABEL = {"observe": "observe (diagnostic seul)",
                           "approve": "approve (approbation humaine)",
                           "execute": "execute (auto-remédiation)"}
            ceil_line = (f"\n• Autonomie : <b>{_CEIL_LABEL.get(st.get('ceiling'), st.get('ceiling'))}</b>"
                         f"\n• Diagnostic auto : {'on' if st.get('diagnose') else 'off'}"
                         f"\n• Règles : {st.get('rules')} · approbations en attente : {st.get('pending')}")
        except CoreUnavailable:
            ceil_line = "\n• Cœur : ⚠️ injoignable"
        send(token, chat_id, f"✅ Atlas en ligne ({bot['version']}).\n"
                             f"• Uptime : {up}\n"
                             f"• Verrou : {verrou}\n"
                             f"• Auto-lock : {AUTO_LOCK_SECONDS} s\n"
                             f"• Catalogue : {len(bot['cat'].list())} opération(s)"
                             f"{ceil_line}")
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
        _safe(token, chat_id, lambda: cmd_run(actor, parts[1], parts[2:]))
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

    # Chats où poster les alertes/approbations du moteur (RM1813). Défaut = whitelist
    # (bot privé : chat_id == user_id en messages directs).
    alert_raw = os.environ.get("ATLAS_ALERT_CHAT", "")
    alert_chats = {int(x) for x in alert_raw.replace(" ", "").split(",") if x.lstrip("-").isdigit()}
    if not alert_chats:
        alert_chats = set(whitelist)

    bot = {"token": token, "whitelist": whitelist, "lock": lock, "cat": cat,
           "alert_chats": alert_chats, "start": time.time(), "version": VERSION}

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
            cb = upd.get("callback_query")
            if cb:
                print(f"  → update {upd['update_id']} : callback {cb.get('data')!r}")
                try:
                    handle_callback(bot, cb)
                except Exception as e:
                    print(f"  ⚠ callback erreur : {e}")
                continue
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

        # Tire les notifications du cœur (alertes + approbations P2) et les poste.
        try:
            poll_and_notify(bot)
        except Exception as e:
            print(f"  ⚠ poll cœur erreur : {e}")


if __name__ == "__main__":
    main()
