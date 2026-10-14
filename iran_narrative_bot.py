#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ربات اختصاصی تیم IRAN NARRATIVE  (پلتفرم روبیکا)
==================================================

معماری:
    Database        -> ذخیره‌سازی در SQLite (تنظیمات، ادمین‌ها، پست‌ها، نظرات، نشست‌ها)
    Transport       -> رابط انتزاعی ارسال پیام/فایل (برای انتقال به پلتفرم دیگر فقط این را پیاده‌سازی کنید)
    RubikaTransport -> پیاده‌سازی Transport برای Bot API روبیکا (v3)
    BotCore         -> منطق ربات (ماشین حالت)، مستقل از پلتفرم

اجرا:
    pip install requests
    export RUBIKA_BOT_TOKEN="توکن ربات از @botfather"
    python iran_narrative_bot.py
"""

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

import requests

# ----------------------------------------------------------------------------
# تنظیمات اولیه
# ----------------------------------------------------------------------------
BOT_TOKEN = os.environ.get("RUBIKA_BOT_TOKEN", "")
DB_PATH = os.environ.get("BOT_DB_PATH", "bot_data.sqlite3")

DEFAULT_BOT_NAME = "IRAN NARRATIVE"
DEFAULT_ADMIN_NAME = "محمد امین روحانی"
DEFAULT_ADMIN_PASSWORD = "@IRAN NARRATIVE"

DEFAULT_WELCOME = (
    "به ربات اختصاصی تیم IRAN NARRATIVE خوش آمدید "
    "جهت بهره برداری از امکانات ربات روی یکی از دکمه های زیر کلیک کنید"
)
DEFAULT_ABOUT = "هنوز متنی برای «درباره ما» ثبت نشده است."
DEFAULT_MAINTENANCE = "⛔️ ربات در حال حاضر غیرفعال است. لطفاً بعداً مراجعه کنید."

MAX_LOGIN_FAILS = 3          # تعداد تلاش ناموفق مجاز
LOCK_SECONDS = 300           # مدت قفل شدن ورود ادمین پس از تلاش‌های ناموفق
MIN_PASSWORD_LEN = 6
MAX_FEEDBACK_LEN = 2000
MAX_POSTS_IN_LIST = 30
POLL_INTERVAL = 1.0

VIDEO_EXT = {".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".3gp"}

# ----------------------------------------------------------------------------
# برچسب دکمه‌ها
# ----------------------------------------------------------------------------
BTN_CONTACTS = "👥 مخاطبین"
BTN_ADMINS = "🛡 ادمین‌ها"
BTN_HOME = "🏠 منوی اصلی"

BTN_U_POSTS = "📂 لیست پست ها"
BTN_U_FEEDBACK = "✉️ ارسال نظرات"
BTN_U_ABOUT = "ℹ️ درباره ما"
BTN_U_BACK = "↩️ بازگشت به منوی مخاطبین"

BTN_A_RENAME = "✏️ تغییر نام ربات"
BTN_A_PASS = "🔑 تغییر رمز ورود"
BTN_A_ADDADMIN = "➕ افزودن ادمین"
BTN_A_ADDPOST = "📤 افزودن فایل/ویدیو"
BTN_A_DELPOST = "🗑 حذف پست"
BTN_A_OFF = "⛔️ غیرفعال کردن ربات"
BTN_A_ON = "✅ فعال کردن ربات"
BTN_A_FEEDBACKS = "📥 دریافت نظرات"
BTN_A_ABOUT = "📝 ویرایش درباره ما"
BTN_A_LOGOUT = "🚪 خروج از حساب ادمین"
BTN_A_BACK = "↩️ بازگشت به منوی ادمین"

log = logging.getLogger("iran_narrative_bot")


# ----------------------------------------------------------------------------
# ابزارهای کمکی
# ----------------------------------------------------------------------------
_CHAR_MAP = str.maketrans({
    "ي": "ی", "ك": "ک", "ۀ": "ه", "ة": "ه",
    "\u200c": " ", "\u200f": "", "\u200e": "",
})


def normalize(s: str) -> str:
    """یکسان‌سازی حروف عربی/فارسی و فاصله‌ها برای مقایسه نام‌ها."""
    s = (s or "").translate(_CHAR_MAP)
    return re.sub(r"\s+", " ", s).strip().casefold()


def plain(s: str) -> str:
    """حذف ایموجی و علائم برای مقایسه متن دکمه‌ها."""
    return normalize(re.sub(r"[^\w\s]", "", normalize(s), flags=re.UNICODE))


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 200_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    candidate = hash_password(password, salt).split("$", 1)[1]
    return hmac.compare_digest(candidate, digest)


def fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


# ----------------------------------------------------------------------------
# دیتابیس
# ----------------------------------------------------------------------------
class Database:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self._init_schema()

    def _exec(self, sql: str, params=(), fetch: Optional[str] = None):
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            if fetch == "one":
                return cur.fetchone()
            if fetch == "all":
                return cur.fetchall()
            return cur

    def _init_schema(self):
        with self.lock:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name_norm TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT NOT NULL,
                file_name TEXT,
                file_type TEXT NOT NULL,
                caption TEXT,
                created_by TEXT,
                created_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS feedbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at REAL NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS sessions (
                chat_id TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'MAIN',
                data TEXT NOT NULL DEFAULT '{}',
                is_admin INTEGER NOT NULL DEFAULT 0,
                admin_name TEXT NOT NULL DEFAULT '',
                fails INTEGER NOT NULL DEFAULT 0,
                lock_until REAL NOT NULL DEFAULT 0);
            """)
            self.conn.commit()
        # مقداردهی پیش‌فرض (فقط در اولین اجرا)
        defaults = {
            "bot_name": DEFAULT_BOT_NAME,
            "password_hash": hash_password(DEFAULT_ADMIN_PASSWORD),
            "is_active": "1",
            "about_text": DEFAULT_ABOUT,
            "welcome_text": DEFAULT_WELCOME,
            "maintenance_text": DEFAULT_MAINTENANCE,
        }
        for k, v in defaults.items():
            self._exec("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, v))
        self.add_admin(DEFAULT_ADMIN_NAME)

    # --- تنظیمات ---
    def get_setting(self, key: str, default: str = "") -> str:
        row = self._exec("SELECT value FROM settings WHERE key=?", (key,), "one")
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        self._exec("INSERT INTO settings(key, value) VALUES (?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def is_active(self) -> bool:
        return self.get_setting("is_active", "1") == "1"

    # --- ادمین‌ها ---
    def find_admin(self, name: str):
        return self._exec("SELECT * FROM admins WHERE name_norm=?", (normalize(name),), "one")

    def add_admin(self, name: str) -> bool:
        cur = self._exec("INSERT OR IGNORE INTO admins(name_norm, display_name, created_at) "
                         "VALUES (?, ?, ?)", (normalize(name), name.strip(), time.time()))
        return cur.rowcount > 0

    def list_admins(self):
        return self._exec("SELECT display_name FROM admins ORDER BY id", fetch="all")

    # --- پست‌ها ---
    def add_post(self, file_id, file_name, file_type, caption, created_by) -> int:
        cur = self._exec("INSERT INTO posts(file_id, file_name, file_type, caption, created_by, created_at) "
                         "VALUES (?, ?, ?, ?, ?, ?)",
                         (file_id, file_name, file_type, caption, created_by, time.time()))
        return cur.lastrowid

    def list_posts(self, limit: int = MAX_POSTS_IN_LIST):
        return self._exec("SELECT * FROM posts ORDER BY id DESC LIMIT ?", (limit,), "all")

    def get_post(self, post_id: int):
        return self._exec("SELECT * FROM posts WHERE id=?", (post_id,), "one")

    def delete_post(self, post_id: int) -> bool:
        return self._exec("DELETE FROM posts WHERE id=?", (post_id,)).rowcount > 0

    # --- نظرات ---
    def add_feedback(self, chat_id: str, text: str):
        self._exec("INSERT INTO feedbacks(chat_id, text, created_at) VALUES (?, ?, ?)",
                   (chat_id, text, time.time()))

    def unread_count(self) -> int:
        return self._exec("SELECT COUNT(*) AS c FROM feedbacks WHERE is_read=0", fetch="one")["c"]

    def recent_feedbacks(self, limit: int = 20):
        return self._exec("SELECT * FROM feedbacks ORDER BY id DESC LIMIT ?", (limit,), "all")

    def mark_feedbacks_read(self):
        self._exec("UPDATE feedbacks SET is_read=1 WHERE is_read=0")

    # --- نشست‌ها ---
    def get_session(self, chat_id: str) -> dict:
        row = self._exec("SELECT * FROM sessions WHERE chat_id=?", (chat_id,), "one")
        if not row:
            return {"state": "MAIN", "data": {}, "is_admin": 0, "admin_name": "",
                    "fails": 0, "lock_until": 0.0}
        d = dict(row)
        d["data"] = json.loads(d["data"] or "{}")
        return d

    def save_session(self, chat_id: str, **fields):
        cur = self.get_session(chat_id)
        cur.update(fields)
        self._exec(
            "INSERT OR REPLACE INTO sessions(chat_id, state, data, is_admin, admin_name, fails, lock_until) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (chat_id, cur["state"], json.dumps(cur["data"], ensure_ascii=False),
             int(cur["is_admin"]), cur["admin_name"], cur["fails"], cur["lock_until"]))


# ----------------------------------------------------------------------------
# لایه انتقال (Transport)
# ----------------------------------------------------------------------------
@dataclass
class Incoming:
    chat_id: str
    text: str = ""
    message_id: Optional[str] = None
    file_id: Optional[str] = None
    file_name: Optional[str] = None


Keypad = Optional[List[List[str]]]


class Transport(ABC):
    """برای انتقال ربات به پلتفرم دیگر، فقط این سه متد را پیاده‌سازی کنید."""

    @abstractmethod
    def send_text(self, chat_id: str, text: str, keypad: Keypad = None) -> bool: ...

    @abstractmethod
    def send_file(self, chat_id: str, file_id: str, caption: str = "", keypad: Keypad = None) -> bool: ...

    @abstractmethod
    def delete_message(self, chat_id: str, message_id: str) -> bool: ...


class RubikaTransport(Transport):
    def __init__(self, token: str):
        self.base = f"https://botapi.rubika.ir/v3/{token}/"
        self.session = requests.Session()

    def call(self, method: str, payload: Optional[dict] = None, retries: int = 3) -> Optional[dict]:
        for attempt in range(retries):
            try:
                resp = self.session.post(self.base + method, json=payload or {}, timeout=30)
                data = resp.json()
                if data.get("status") == "OK":
                    return data.get("data", {})
                log.warning("خطای API در %s: %s", method, data)
                return None
            except (requests.RequestException, ValueError) as exc:
                log.warning("خطای شبکه در %s (تلاش %d): %s", method, attempt + 1, exc)
                time.sleep(2 * (attempt + 1))
        return None

    @staticmethod
    def _keypad(rows: List[List[str]]) -> dict:
        return {
            "rows": [
                {"buttons": [{"id": f"b_{r}_{c}", "type": "Simple", "button_text": label}
                             for c, label in enumerate(row)]}
                for r, row in enumerate(rows)
            ],
            "resize_keyboard": True,
            "on_time_keyboard": False,
        }

    def send_text(self, chat_id, text, keypad=None) -> bool:
        payload = {"chat_id": chat_id, "text": text}
        if keypad:
            payload["chat_keypad"] = self._keypad(keypad)
            payload["chat_keypad_type"] = "New"
        return self.call("sendMessage", payload) is not None

    def send_file(self, chat_id, file_id, caption="", keypad=None) -> bool:
        payload = {"chat_id": chat_id, "file_id": file_id}
        if caption:
            payload["text"] = caption
        if keypad:
            payload["chat_keypad"] = self._keypad(keypad)
            payload["chat_keypad_type"] = "New"
        return self.call("sendFile", payload) is not None

    def delete_message(self, chat_id, message_id) -> bool:
        return self.call("deleteMessage", {"chat_id": chat_id, "message_id": message_id}) is not None


def parse_update(upd: dict) -> Optional[Incoming]:
    """تبدیل آپدیت خام روبیکا به Incoming."""
    utype = upd.get("type")
    chat_id = upd.get("chat_id")
    if not chat_id:
        return None
    if utype == "StartedBot":
        return Incoming(chat_id=chat_id, text="/start")
    if utype != "NewMessage":
        return None
    msg = upd.get("new_message") or {}
    if msg.get("sender_type") not in (None, "User"):
        return None
    file = msg.get("file") or {}
    return Incoming(
        chat_id=chat_id,
        text=msg.get("text") or "",
        message_id=msg.get("message_id"),
        file_id=file.get("file_id"),
        file_name=file.get("file_name"),
    )


# ----------------------------------------------------------------------------
# هسته ربات
# ----------------------------------------------------------------------------
class BotCore:
    def __init__(self, db: Database, tx: Transport):
        self.db = db
        self.tx = tx
        self.handlers: Dict[str, Callable] = {
            "MAIN": self.st_main,
            "LOGIN_NAME": self.st_login_name,
            "LOGIN_PASS": self.st_login_pass,
            "USER_MENU": self.st_user_menu,
            "USER_POSTS": self.st_user_posts,
            "USER_FEEDBACK": self.st_user_feedback,
            "A_MENU": self.st_admin_menu,
            "A_RENAME": self.st_a_rename,
            "A_PASS1": self.st_a_pass1,
            "A_PASS2": self.st_a_pass2,
            "A_ADDADMIN": self.st_a_addadmin,
            "A_POST_FILE": self.st_a_post_file,
            "A_POST_CAPTION": self.st_a_post_caption,
            "A_DELPOST": self.st_a_delpost,
            "A_ABOUT": self.st_a_about,
        }

    # ---------- ابزارها ----------
    @staticmethod
    def _is(text: str, *buttons: str) -> bool:
        p = plain(text)
        return any(p == plain(b) for b in buttons)

    def reply(self, chat_id: str, text: str, keypad: Keypad = None):
        self.tx.send_text(chat_id, text, keypad)

    def reply_long(self, chat_id: str, text: str, keypad: Keypad = None, chunk: int = 3500):
        parts = [text[i:i + chunk] for i in range(0, len(text), chunk)] or [""]
        for i, part in enumerate(parts):
            self.tx.send_text(chat_id, part, keypad if i == len(parts) - 1 else None)

    def go(self, chat_id: str, state: str, **data):
        self.db.save_session(chat_id, state=state, data=data)

    @staticmethod
    def _post_label(p) -> str:
        icon = "🎬" if p["file_type"] == "video" else "📄"
        title = (p["caption"] or p["file_name"] or "بدون عنوان").strip().splitlines()[0][:30]
        return f"{icon} {p['id']} | {title}"

    @staticmethod
    def _post_id_from_label(text: str) -> Optional[int]:
        m = re.match(r"^\S+\s+(\d+)\s*\|", text.strip())
        return int(m.group(1)) if m else None

    # ---------- نقطه ورود ----------
    def handle(self, inc: Incoming):
        chat = inc.chat_id
        text = (inc.text or "").strip()
        sess = self.db.get_session(chat)

        if text.lower() in ("/start", "start") or self._is(text, BTN_HOME):
            return self.show_main(chat)

        state = sess["state"]

        # دسترسی به حالت‌های ادمین فقط با ورود موفق
        if state.startswith("A_") and not sess["is_admin"]:
            return self.show_main(chat)

        # حالت تعمیر برای مخاطبین
        if state.startswith("USER_") and not self.db.is_active():
            self.reply(chat, self.db.get_setting("maintenance_text", DEFAULT_MAINTENANCE))
            return self.show_main(chat)

        # دکمه‌های بازگشت
        if state.startswith("A_") and state != "A_MENU" and self._is(text, BTN_A_BACK):
            return self.show_admin_menu(chat)
        if state in ("USER_POSTS", "USER_FEEDBACK") and self._is(text, BTN_U_BACK):
            return self.open_user_menu(chat)

        self.handlers.get(state, self.st_main)(chat, text, inc, sess)

    # ---------- منوی اصلی ----------
    def show_main(self, chat: str):
        self.go(chat, "MAIN")
        name = self.db.get_setting("bot_name", DEFAULT_BOT_NAME)
        self.reply(chat, f"🤖 ربات {name}\nلطفاً یکی از گزینه‌ها را انتخاب کنید:",
                   [[BTN_CONTACTS, BTN_ADMINS]])

    def st_main(self, chat, text, inc, sess):
        if self._is(text, BTN_CONTACTS):
            if not self.db.is_active():
                self.reply(chat, self.db.get_setting("maintenance_text", DEFAULT_MAINTENANCE))
                return
            return self.open_user_menu(chat)
        if self._is(text, BTN_ADMINS):
            return self.open_admin_entry(chat, sess)
        self.show_main(chat)

    # ======================================================================
    # بخش مخاطبین
    # ======================================================================
    def open_user_menu(self, chat: str):
        self.go(chat, "USER_MENU")
        self.reply(chat, self.db.get_setting("welcome_text", DEFAULT_WELCOME),
                   [[BTN_U_POSTS], [BTN_U_FEEDBACK, BTN_U_ABOUT], [BTN_HOME]])

    def st_user_menu(self, chat, text, inc, sess):
        if self._is(text, BTN_U_POSTS):
            return self.show_user_posts(chat)
        if self._is(text, BTN_U_FEEDBACK):
            self.go(chat, "USER_FEEDBACK")
            return self.reply(chat, "✍️ نظر، پیشنهاد یا انتقاد خود را بنویسید و ارسال کنید:",
                              [[BTN_U_BACK]])
        if self._is(text, BTN_U_ABOUT):
            return self.reply(chat, "ℹ️ درباره ما\n\n" + self.db.get_setting("about_text", DEFAULT_ABOUT),
                              [[BTN_U_POSTS], [BTN_U_FEEDBACK, BTN_U_ABOUT], [BTN_HOME]])
        self.open_user_menu(chat)

    def show_user_posts(self, chat: str):
        posts = self.db.list_posts()
        if not posts:
            return self.reply(chat, "هنوز پستی ثبت نشده است.", [[BTN_U_BACK]])
        self.go(chat, "USER_POSTS")
        rows = [[self._post_label(p)] for p in posts] + [[BTN_U_BACK]]
        self.reply(chat, "📂 یکی از پست‌ها را برای دریافت انتخاب کنید:", rows)

    def st_user_posts(self, chat, text, inc, sess):
        post_id = self._post_id_from_label(text)
        post = self.db.get_post(post_id) if post_id else None
        if not post:
            return self.show_user_posts(chat)
        ok = self.tx.send_file(chat, post["file_id"], post["caption"] or "")
        if not ok:
            self.reply(chat, "⚠️ ارسال فایل با خطا مواجه شد. لطفاً بعداً دوباره تلاش کنید.")

    def st_user_feedback(self, chat, text, inc, sess):
        if not text:
            return self.reply(chat, "لطفاً نظر خود را به صورت متن بفرستید.")
        if len(text) > MAX_FEEDBACK_LEN:
            return self.reply(chat, f"متن بیش از حد طولانی است (حداکثر {MAX_FEEDBACK_LEN} نویسه).")
        self.db.add_feedback(chat, text)
        self.reply(chat, "✅ نظر شما ثبت شد. سپاس از همراهی شما 🌹")
        self.open_user_menu(chat)

    # ======================================================================
    # ورود ادمین
    # ======================================================================
    def open_admin_entry(self, chat: str, sess: dict):
        if sess["is_admin"]:
            return self.show_admin_menu(chat)
        remaining = int(sess["lock_until"] - time.time())
        if remaining > 0:
            self.reply(chat, f"⏳ به دلیل تلاش‌های ناموفق، ورود تا {remaining // 60 + 1} دقیقه دیگر مسدود است.")
            return self.show_main(chat)
        self.go(chat, "LOGIN_NAME")
        self.reply(chat, "👤 نام ادمین را وارد کنید:", [[BTN_HOME]])

    def _login_fail(self, chat: str, sess: dict, msg: str):
        fails = sess["fails"] + 1
        if fails >= MAX_LOGIN_FAILS:
            self.db.save_session(chat, fails=0, lock_until=time.time() + LOCK_SECONDS)
            self.reply(chat, "⛔️ تعداد تلاش‌های ناموفق بیش از حد مجاز بود. ورود موقتاً مسدود شد.")
            return self.show_main(chat)
        self.db.save_session(chat, fails=fails)
        self.reply(chat, f"{msg}\nتلاش باقی‌مانده: {MAX_LOGIN_FAILS - fails}", [[BTN_HOME]])

    def st_login_name(self, chat, text, inc, sess):
        admin = self.db.find_admin(text)
        if not admin:
            return self._login_fail(chat, sess, "❌ این نام در لیست ادمین‌ها نیست.")
        self.go(chat, "LOGIN_PASS", name=admin["display_name"])
        self.reply(chat, "🔐 رمز عبور را وارد کنید:", [[BTN_HOME]])

    def st_login_pass(self, chat, text, inc, sess):
        if inc.message_id:
            self.tx.delete_message(chat, inc.message_id)  # تلاش برای حذف پیام حاوی رمز
        if not verify_password(text.strip(), self.db.get_setting("password_hash")):
            return self._login_fail(chat, sess, "❌ رمز عبور اشتباه است.")
        self.db.save_session(chat, is_admin=1, admin_name=sess["data"].get("name", ""), fails=0)
        self.reply(chat, "✅ با موفقیت وارد شدید.")
        self.show_admin_menu(chat)

    # ======================================================================
    # بخش ادمین‌ها
    # ======================================================================
    def show_admin_menu(self, chat: str):
        self.go(chat, "A_MENU")
        toggle = BTN_A_OFF if self.db.is_active() else BTN_A_ON
        status = "فعال ✅" if self.db.is_active() else "غیرفعال ⛔️"
        text = (f"🛡 پنل مدیریت\n"
                f"نام ربات: {self.db.get_setting('bot_name')}\n"
                f"وضعیت: {status}\n"
                f"نظرات خوانده‌نشده: {self.db.unread_count()}")
        self.reply(chat, text, [
            [BTN_A_ADDPOST, BTN_A_DELPOST],
            [BTN_A_FEEDBACKS, BTN_A_ABOUT],
            [BTN_A_RENAME, BTN_A_PASS],
            [BTN_A_ADDADMIN, toggle],
            [BTN_A_LOGOUT, BTN_HOME],
        ])

    def st_admin_menu(self, chat, text, inc, sess):
        back = [[BTN_A_BACK]]
        if self._is(text, BTN_A_RENAME):
            self.go(chat, "A_RENAME")
            return self.reply(chat, "نام جدید ربات را بفرستید:", back)
        if self._is(text, BTN_A_PASS):
            self.go(chat, "A_PASS1")
            return self.reply(chat, f"🔑 رمز عبور جدید را بفرستید (حداقل {MIN_PASSWORD_LEN} نویسه):", back)
        if self._is(text, BTN_A_ADDADMIN):
            self.go(chat, "A_ADDADMIN")
            names = "، ".join(r["display_name"] for r in self.db.list_admins())
            return self.reply(chat, f"ادمین‌های فعلی: {names}\n\nنام ادمین جدید را بفرستید:", back)
        if self._is(text, BTN_A_ADDPOST):
            self.go(chat, "A_POST_FILE")
            return self.reply(chat, "📤 فایل یا ویدیوی مورد نظر را ارسال کنید:", back)
        if self._is(text, BTN_A_DELPOST):
            return self.show_delete_posts(chat)
        if self._is(text, BTN_A_OFF):
            self.db.set_setting("is_active", "0")
            self.reply(chat, "⛔️ ربات برای مخاطبین غیرفعال شد (حالت تعمیر).")
            return self.show_admin_menu(chat)
        if self._is(text, BTN_A_ON):
            self.db.set_setting("is_active", "1")
            self.reply(chat, "✅ ربات دوباره فعال شد.")
            return self.show_admin_menu(chat)
        if self._is(text, BTN_A_FEEDBACKS):
            return self.show_feedbacks(chat)
        if self._is(text, BTN_A_ABOUT):
            self.go(chat, "A_ABOUT")
            cur = self.db.get_setting("about_text", DEFAULT_ABOUT)
            self.reply_long(chat, f"متن فعلی «درباره ما»:\n\n{cur}")
            return self.reply(chat, "متن جدید را بفرستید تا جایگزین شود:", back)
        if self._is(text, BTN_A_LOGOUT):
            self.db.save_session(chat, is_admin=0, admin_name="")
            self.reply(chat, "🚪 از حساب ادمین خارج شدید.")
            return self.show_main(chat)
        self.show_admin_menu(chat)

    def st_a_rename(self, chat, text, inc, sess):
        if not text or len(text) > 60:
            return self.reply(chat, "نام نامعتبر است (۱ تا ۶۰ نویسه).")
        self.db.set_setting("bot_name", text)
        self.reply(chat, f"✅ نام ربات به «{text}» تغییر کرد.")
        self.show_admin_menu(chat)

    def st_a_pass1(self, chat, text, inc, sess):
        if inc.message_id:
            self.tx.delete_message(chat, inc.message_id)
        pw = text.strip()
        if len(pw) < MIN_PASSWORD_LEN:
            return self.reply(chat, f"رمز باید حداقل {MIN_PASSWORD_LEN} نویسه باشد. دوباره بفرستید:")
        self.go(chat, "A_PASS2", new=hash_password(pw), pw_check=hashlib.sha256(pw.encode()).hexdigest())
        self.reply(chat, "برای تأیید، رمز جدید را یک بار دیگر بفرستید:", [[BTN_A_BACK]])

    def st_a_pass2(self, chat, text, inc, sess):
        if inc.message_id:
            self.tx.delete_message(chat, inc.message_id)
        if hashlib.sha256(text.strip().encode()).hexdigest() != sess["data"].get("pw_check"):
            self.go(chat, "A_PASS1")
            return self.reply(chat, "❌ رمزها یکسان نبودند. رمز جدید را از ابتدا بفرستید:", [[BTN_A_BACK]])
        self.db.set_setting("password_hash", sess["data"]["new"])
        self.reply(chat, "✅ رمز ورود ادمین تغییر کرد.")
        self.show_admin_menu(chat)

    def st_a_addadmin(self, chat, text, inc, sess):
        if not text or len(text) > 60:
            return self.reply(chat, "نام نامعتبر است.")
        if self.db.add_admin(text):
            self.reply(chat, f"✅ «{text}» به ادمین‌ها اضافه شد.")
        else:
            self.reply(chat, "این نام قبلاً در لیست ادمین‌ها بوده است.")
        self.show_admin_menu(chat)

    def st_a_post_file(self, chat, text, inc, sess):
        if not inc.file_id:
            return self.reply(chat, "لطفاً یک فایل یا ویدیو ارسال کنید (نه متن).")
        name = inc.file_name or ""
        ext = os.path.splitext(name)[1].lower()
        ftype = "video" if ext in VIDEO_EXT else "file"
        self.go(chat, "A_POST_CAPTION", file_id=inc.file_id, file_name=name, file_type=ftype)
        self.reply(chat, "📝 کپشن پست را بفرستید (برای بدون کپشن، علامت - را بفرستید):", [[BTN_A_BACK]])

    def st_a_post_caption(self, chat, text, inc, sess):
        d = sess["data"]
        caption = "" if text.strip() == "-" else text
        pid = self.db.add_post(d["file_id"], d["file_name"], d["file_type"], caption, sess["admin_name"])
        self.reply(chat, f"✅ پست شماره {pid} ثبت شد.")
        self.show_admin_menu(chat)

    def show_delete_posts(self, chat: str):
        posts = self.db.list_posts()
        if not posts:
            self.reply(chat, "پستی برای حذف وجود ندارد.")
            return self.show_admin_menu(chat)
        self.go(chat, "A_DELPOST")
        rows = [[self._post_label(p)] for p in posts] + [[BTN_A_BACK]]
        self.reply(chat, "🗑 پستی را که می‌خواهید حذف شود انتخاب کنید:", rows)

    def st_a_delpost(self, chat, text, inc, sess):
        pid = self._post_id_from_label(text)
        if pid and self.db.delete_post(pid):
            self.reply(chat, f"✅ پست {pid} حذف شد.")
        else:
            self.reply(chat, "پست نامعتبر است.")
        self.show_delete_posts(chat)

    def show_feedbacks(self, chat: str):
        items = self.db.recent_feedbacks()
        if not items:
            self.reply(chat, "هنوز نظری ثبت نشده است.")
            return self.show_admin_menu(chat)
        blocks = []
        for f in items:
            mark = "🆕" if not f["is_read"] else "💬"
            blocks.append(f"{mark} #{f['id']} — {fmt_time(f['created_at'])}\n{f['text']}")
        self.reply_long(chat, "📥 آخرین نظرات:\n\n" + "\n──────────\n".join(blocks))
        self.db.mark_feedbacks_read()
        self.show_admin_menu(chat)

    def st_a_about(self, chat, text, inc, sess):
        if not text:
            return self.reply(chat, "لطفاً متن را به صورت پیام بفرستید.")
        self.db.set_setting("about_text", text)
        self.reply(chat, "✅ متن «درباره ما» به‌روزرسانی شد.")
        self.show_admin_menu(chat)


# ----------------------------------------------------------------------------
# حلقه دریافت پیام‌ها (Polling)
# ----------------------------------------------------------------------------
def run_polling(core: BotCore, tx: RubikaTransport, db: Database):
    offset = db.get_setting("offset_id", "")
    seen = deque(maxlen=2000)
    log.info("ربات شروع به کار کرد…")
    while True:
        payload = {"limit": 50}
        if offset:
            payload["offset_id"] = offset
        data = tx.call("getUpdates", payload)
        if data is None:
            time.sleep(3)
            continue
        for upd in data.get("updates", []):
            inc = parse_update(upd)
            if not inc:
                continue
            key = (inc.chat_id, inc.message_id)
            if inc.message_id and key in seen:
                continue
            seen.append(key)
            try:
                core.handle(inc)
            except Exception:  # یک خطا نباید کل ربات را از کار بیندازد
                log.exception("خطا در پردازش پیام")
        nxt = data.get("next_offset_id")
        if nxt:
            offset = nxt
            db.set_setting("offset_id", nxt)
        time.sleep(POLL_INTERVAL)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not BOT_TOKEN:
        raise SystemExit("متغیر محیطی RUBIKA_BOT_TOKEN تنظیم نشده است.")
    db = Database(DB_PATH)
    tx = RubikaTransport(BOT_TOKEN)
    core = BotCore(db, tx)
    run_polling(core, tx, db)


if __name__ == "__main__":
    main()
