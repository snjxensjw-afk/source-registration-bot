import os
import sqlite3
import hashlib
import hmac
import secrets
import time
import re
import asyncio
from contextlib import closing

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from supabase import create_client, Client
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import uvicorn

# Required environment variables:
# TELEGRAM_BOT_TOKEN       = token from @BotFather
# BOT_USERNAME             = bot username without @, e.g. SourceHubAuthBot
# SUPABASE_URL             = https://....supabase.co
# SUPABASE_SERVICE_ROLE_KEY= SERVER ONLY; never put this in index.html
# SUPABASE_PUBLISHABLE_KEY = sb_publishable_... (used only for sign-in)
# AUTH_SECRET              = long random server secret
# CORS_ORIGINS             = https://your-site.netlify.app (comma separated)
# PORT                     = 8080 (optional)

BOT_TOKEN = os.environ["8758741736:AAHeteDQ1CNn8b06-meF7P0lE6q2B_jgTAA"]
BOT_USERNAME = os.getenv("@sourcereg_bot", "").lstrip("@")
SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
SUPABASE_PUBLISHABLE_KEY = os.environ["SUPABASE_PUBLISHABLE_KEY"]
AUTH_SECRET = os.environ["AUTH_SECRET"].encode()
DB_PATH = os.getenv("BOT_DB", "sourcehub_bot.sqlite3")
PORT = int(os.getenv("PORT", "8080"))

origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()]
if not origins:
    origins = ["https://s0urse.netlify.app"]

admin_sb: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
auth_sb: Client = create_client(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY)

app = FastAPI(title="SourceHub Telegram Auth", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Content-Type"],
)


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_db():
    with closing(db()) as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                telegram_id INTEGER PRIMARY KEY,
                supabase_user_id TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_codes_lookup ON codes(code_hash, used, expires_at);
            CREATE TABLE IF NOT EXISTS api_limits (
                key TEXT PRIMARY KEY,
                window_start INTEGER NOT NULL,
                hits INTEGER NOT NULL
            );
            """
        )
        con.commit()


def hash_code(code: str) -> str:
    return hmac.new(AUTH_SECRET, code.encode(), hashlib.sha256).hexdigest()


def account_password(telegram_id: int) -> str:
    # Deterministic secret password: the user never sees it.
    return hmac.new(AUTH_SECRET, f"account:{telegram_id}".encode(), hashlib.sha256).hexdigest()


def make_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def issue_code(telegram_id: int) -> str:
    now = int(time.time())
    code = make_code()
    with closing(db()) as con:
        con.execute("UPDATE codes SET used=1 WHERE telegram_id=? AND used=0", (telegram_id,))
        con.execute(
            "INSERT INTO codes(telegram_id, code_hash, expires_at, created_at) VALUES(?,?,?,?)",
            (telegram_id, hash_code(code), now + 600, now),
        )
        con.commit()
    return code


def consume_code(code: str):
    now = int(time.time())
    digest = hash_code(code)
    with closing(db()) as con:
        row = con.execute(
            "SELECT id, telegram_id, expires_at FROM codes WHERE code_hash=? AND used=0 ORDER BY id DESC LIMIT 1",
            (digest,),
        ).fetchone()
        if not row or row["expires_at"] < now:
            return None
        con.execute("UPDATE codes SET used=1 WHERE id=?", (row["id"],))
        con.commit()
        return int(row["telegram_id"])


def get_account(telegram_id: int):
    with closing(db()) as con:
        return con.execute("SELECT * FROM accounts WHERE telegram_id=?", (telegram_id,)).fetchone()


def api_rate_limit(ip: str) -> bool:
    now = int(time.time())
    key = f"verify:{ip}"
    with closing(db()) as con:
        row = con.execute("SELECT window_start,hits FROM api_limits WHERE key=?", (key,)).fetchone()
        if not row or now - row["window_start"] >= 60:
            con.execute("INSERT OR REPLACE INTO api_limits(key,window_start,hits) VALUES(?,?,1)", (key, now))
            con.commit()
            return True
        if row["hits"] >= 10:
            return False
        con.execute("UPDATE api_limits SET hits=hits+1 WHERE key=?", (key,))
        con.commit()
        return True


def profile_upsert(user_id: str, username: str, telegram_id: int):
    # Service-role operation on the server; browser never gets this key.
    result = admin_sb.table("profiles").upsert(
        {
            "id": user_id,
            "username": username,
            "bio": "Автор SourceHub",
            "telegram": str(telegram_id),
        },
        on_conflict="id",
    ).execute()
    return result


def create_or_get_supabase_user(telegram_id: int, username: str | None):
    account = get_account(telegram_id)
    password = account_password(telegram_id)

    if account:
        user_id = account["supabase_user_id"]
        stored_username = account["username"]
        return user_id, stored_username, password

    clean = (username or f"tg_{telegram_id}").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,30}", clean):
        raise ValueError("Ник: 3–30 символов, только латиница, цифры, _ или -.")

    email = f"tg_{telegram_id}@sourcehub.local"
    try:
        created = admin_sb.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": True,
            "user_metadata": {
                "username": clean,
                "telegram_id": telegram_id,
            },
        })
        user = getattr(created, "user", None) or created.get("user")
        user_id = str(user.id if hasattr(user, "id") else user["id"])
    except Exception as exc:
        # Do not leak provider internals to the browser.
        raise RuntimeError("Не удалось создать аккаунт в Supabase.") from exc

    with closing(db()) as con:
        con.execute(
            "INSERT INTO accounts(telegram_id,supabase_user_id,username,created_at) VALUES(?,?,?,?)",
            (telegram_id, user_id, clean, int(time.time())),
        )
        con.commit()

    try:
        profile_upsert(user_id, clean, telegram_id)
    except Exception:
        # Auth account remains valid; profile fallback in the frontend can recover it.
        pass
    return user_id, clean, password


class VerifyBody(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")
    username: str | None = Field(default=None, max_length=30)
    mode: str = Field(default="login", max_length=10)


@app.get("/health")
async def health():
    return {"ok": True, "service": "sourcehub-telegram-auth"}


@app.post("/api/auth/verify")
async def verify(body: VerifyBody, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not api_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Слишком много попыток. Подожди минуту.")

    telegram_id = consume_code(body.code)
    if telegram_id is None:
        raise HTTPException(status_code=400, detail="Код неверный, уже использован или просрочен.")

    try:
        user_id, stored_username, password = create_or_get_supabase_user(telegram_id, body.username)
        # Login through the public client so the returned session is a normal user session.
        result = auth_sb.auth.sign_in_with_password({
            "email": f"tg_{telegram_id}@sourcehub.local",
            "password": password,
        })
        session = getattr(result, "session", None) or result.get("session")
        user = getattr(result, "user", None) or result.get("user")
        if not session:
            raise RuntimeError("No auth session")
        access = session.access_token if hasattr(session, "access_token") else session["access_token"]
        refresh = session.refresh_token if hasattr(session, "refresh_token") else session["refresh_token"]
        uid = user.id if hasattr(user, "id") else user["id"]
        return {
            "ok": True,
            "access_token": access,
            "refresh_token": refresh,
            "user": {"id": uid, "username": stored_username, "telegram_id": telegram_id},
        }
    except HTTPException:
        raise
    except Exception as exc:
        print("auth error:", repr(exc))
        raise HTTPException(status_code=500, detail="Не удалось выполнить вход. Попробуй получить новый код.")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.effective_user or not update.effective_chat:
        return
    code = issue_code(update.effective_user.id)
    await update.message.reply_text(
        "SourceHub — код входа\n\n"
        f"Твой одноразовый код: {code}\n\n"
        "Код действует 10 минут и работает только один раз. "
        "Никому его не передавай.\n\n"
        "Вернись на сайт SourceHub и введи этот код."
    )


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Нажми /start, чтобы получить новый 6-значный код для SourceHub.")


async def run_bot():
    telegram_app = Application.builder().token(BOT_TOKEN).build()
    telegram_app.add_handler(CommandHandler("start", start))
    telegram_app.add_handler(CommandHandler("help", help_cmd))
    await telegram_app.initialize()
    await telegram_app.start()
    await telegram_app.updater.start_polling(drop_pending_updates=True)
    try:
        await asyncio.Event().wait()
    finally:
        await telegram_app.updater.stop()
        await telegram_app.stop()
        await telegram_app.shutdown()


async def run_api():
    config = uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def main():
    init_db()
    await asyncio.gather(run_api(), run_bot())


if __name__ == "__main__":
    asyncio.run(main())
