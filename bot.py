"""Telegram Link Bypass & Shortener Bot — entry point.

Run:  python bot.py   (BOT_TOKEN in .env or environment)

v2: per-user languages + stats, cancel button on long bypasses, periodic
health monitoring with admin alerts, dependency auto-updates with a safe
self-restart, heartbeat for Docker's HEALTHCHECK.

v3: per-user daily quotas (premium/admin exempt, custom per-user limits)
and an embedded FastAPI admin dashboard served from the same event loop
(overview, users, cache, health, broadcast, settings).
"""

import asyncio
import contextlib
import logging
import time

from telegram import BotCommand, BotCommandScopeChat, Update
from telegram.ext import (
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from config import APP_VERSION, load_config
from db.factory import create_database
from handlers import admin, callbacks, commands, links
from i18n import LANGUAGES, resolve_lang, tr
from services import updater
from services.bypass_engine import BypassEngine
from services.cache import LinkCache
from services.health import HealthMonitor
from services.quotas import QuotaService
from services.users import UserStore
from utils.ratelimit import RateLimiter

log = logging.getLogger("bot")

CFG = load_config()
logging.getLogger().setLevel(CFG.log_level)


async def _notify_admins(context, text: str) -> None:
    for admin_id in CFG.admin_ids:
        try:
            await context.bot.send_message(admin_id, text)
        except Exception:  # noqa: BLE001 - admin never /started the bot
            pass


# ------------------------------- background jobs -------------------------------

async def heartbeat_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Cheap liveness signal every 5 min (Docker HEALTHCHECK watches it)."""
    monitor = context.bot_data["health"]
    await monitor.ping_db()
    monitor.touch_heartbeat()


async def health_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Full self-diagnostics + admin alert when the status changes."""
    monitor = context.bot_data["health"]
    await monitor.run_checks(deep=True)
    await monitor.notify_if_changed(
        context.bot, CFG, context.bot_data["lang_cache"]
    )


async def update_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Daily dependency check; auto-applies when AUTO_UPDATE=true."""
    db = context.bot_data["db"]
    try:
        updates = await updater.check_updates()
    except Exception as exc:  # noqa: BLE001
        log.warning("update check failed: %s", exc)
        return
    outdated = [u for u in updates if u["outdated"]]
    if not outdated:
        return

    rows = "\n".join(f"• {u['pkg']}: {u['installed']} → {u['latest']}"
                     for u in outdated)
    if CFG.auto_update:
        ok, log_tail = await updater.apply_updates()
        if ok:
            await _notify_admins(
                context, tr(CFG.default_lang, "restart_note")
            )
            await updater.graceful_restart(db)
        else:
            await _notify_admins(
                context, tr(CFG.default_lang, "update_failed",
                            err=log_tail[-400:])
            )
    else:
        stats = await db.stats_all()
        if time.time() - int(stats.get("last_update_notify", 0)) > 20 * 3600:
            await db.stat_set("last_update_notify", int(time.time()))
            await _notify_admins(
                context, tr(CFG.default_lang, "notify_update", pkgs=rows)
            )


async def purge_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    await context.bot_data["cache"].purge_expired(CFG.cache_ttl_hours)


# --------------------------------- lifecycle ----------------------------------

async def post_init(application) -> None:
    """Open the database, register shared services, menu, background jobs."""
    db = await create_database(CFG)

    engine = BypassEngine(
        timeout=CFG.bypass_timeout_seconds,
        api_resolvers=CFG.api_resolvers,
        cf_breaker_threshold=CFG.cf_breaker_threshold,
        cf_breaker_cooldown=CFG.cf_breaker_cooldown_minutes * 60,
    )
    monitor = HealthMonitor(db, engine, CFG.heartbeat_path)

    application.bot_data.update({
        "config": CFG,
        "db": db,
        "engine": engine,
        "cache": LinkCache(db),
        "users": UserStore(db),
        "quotas": QuotaService(db, CFG),
        "limiter": RateLimiter(CFG.cooldown_seconds),
        "health": monitor,
        "tasks": {},        # bypass task registry (cancel buttons)
        "lang_cache": {},   # user_id -> language
        "started_at": time.time(),
    })

    await application.bot.set_my_commands([
        BotCommand("start", "Welcome & quick usage"),
        BotCommand("bypass", "Bypass an ad-shortened link"),
        BotCommand("shorten", "Shorten a long URL"),
        BotCommand("mystats", "Your usage stats"),
        BotCommand("top", "Most active users"),
        BotCommand("quota", "Your daily quota & usage"),
        BotCommand("lang", "Change language"),
        BotCommand("help", "Detailed help & supported sites"),
    ])

    # Admins see the admin commands directly in their command menu.
    admin_commands = [
        BotCommand("stats", "Global statistics"),
        BotCommand("health", "Run a health check now"),
        BotCommand("update", "Check library updates"),
        BotCommand("broadcast", "DM all users"),
        BotCommand("purgecache", "Clear the link cache"),
        BotCommand("setquota", "Set a user's daily limits"),
        BotCommand("setpremium", "Toggle a user's premium"),
    ]
    for admin_id in CFG.admin_ids:
        try:
            await application.bot.set_my_commands(
                admin_commands, scope=BotCommandScopeChat(admin_id)
            )
        except Exception:  # noqa: BLE001 - admin never /started the bot
            pass

    if application.job_queue is not None:
        application.job_queue.run_repeating(
            heartbeat_job, interval=300, first=60
        )
        application.job_queue.run_repeating(
            health_job,
            interval=CFG.healthcheck_interval_minutes * 60,
            first=300,
        )
        application.job_queue.run_repeating(
            update_job, interval=CFG.update_check_interval_hours * 3600,
            first=900,
        )
        application.job_queue.run_repeating(purge_job, interval=1800, first=300)

    # v3: embedded web admin dashboard (same event loop as the bot).
    if CFG.web_enabled:
        from web.dashboard import start_dashboard

        started = start_dashboard(application)
        if started is not None:
            application.bot_data["web_server"] = started[0]
            application.bot_data["web_task"] = started[1]
        elif not CFG.web_password:
            log.warning(
                "WEB_DASHBOARD_ENABLED=true but WEB_ADMIN_PASSWORD is empty "
                "— the dashboard stays off until you set a password."
            )

    log.info(
        "bot v%s initialized — %d bypassers, langs=%s, admins=%s, "
        "auto_update=%s, healthcheck every %smin, quotas=%s/%s per day, "
        "dashboard=%s",
        APP_VERSION,
        len(engine.supported_names()),
        list(LANGUAGES),
        sorted(CFG.admin_ids) or "(none)",
        CFG.auto_update,
        CFG.healthcheck_interval_minutes,
        CFG.daily_bypass_quota or "∞",
        CFG.daily_shorten_quota or "∞",
        f"http://{CFG.web_host}:{CFG.web_port}/" if CFG.web_enabled and CFG.web_password else "off",
    )


async def post_shutdown(application) -> None:
    # v3: stop the dashboard before tearing anything else down.
    server = application.bot_data.get("web_server")
    web_task = application.bot_data.get("web_task")
    if server is not None:
        server.should_exit = True
    if web_task is not None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(web_task, timeout=5)
        log.info("web dashboard stopped")

    db = application.bot_data.get("db")
    if db is not None:
        await db.close()
    log.info("database closed, goodbye")


async def on_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    log.error(
        "unhandled error while processing an update: %s",
        context.error,
        exc_info=context.error,
    )
    if isinstance(update, Update) and update.effective_message:
        try:
            lang = await resolve_lang(
                context.bot_data.get("db"),
                context.bot_data.get("lang_cache", {}),
                update.effective_user,
            )
        except Exception:  # noqa: BLE001
            lang = CFG.default_lang
        try:
            await update.effective_message.reply_text(tr(lang, "error_generic"))
        except Exception:  # noqa: BLE001
            pass


def main() -> None:
    application = (
        ApplicationBuilder()
        .token(CFG.bot_token)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    # user commands
    application.add_handler(CommandHandler("start", commands.cmd_start))
    application.add_handler(CommandHandler("help", commands.cmd_help))
    application.add_handler(CommandHandler("bypass", links.cmd_bypass, block=False))
    application.add_handler(CommandHandler("shorten", links.cmd_shorten, block=False))
    application.add_handler(CommandHandler("mystats", commands.cmd_mystats))
    application.add_handler(CommandHandler("top", commands.cmd_top))
    application.add_handler(CommandHandler("quota", commands.cmd_quota))
    application.add_handler(CommandHandler("lang", commands.cmd_lang))

    # admin commands
    application.add_handler(CommandHandler("stats", admin.cmd_stats))
    application.add_handler(CommandHandler("health", admin.cmd_health, block=False))
    application.add_handler(CommandHandler("update", admin.cmd_update, block=False))
    application.add_handler(
        CommandHandler("broadcast", admin.cmd_broadcast, block=False)
    )
    application.add_handler(CommandHandler("purgecache", admin.cmd_purgecache))
    application.add_handler(CommandHandler("setquota", admin.cmd_setquota))
    application.add_handler(CommandHandler("setpremium", admin.cmd_setpremium))

    # inline buttons (cancel bypass / language picker)
    application.add_handler(CallbackQueryHandler(callbacks.on_callback))

    # private-chat auto-detection (bypass / shorten without commands)
    application.add_handler(
        MessageHandler(
            (filters.TEXT | filters.CAPTION) & filters.ChatType.PRIVATE & ~filters.COMMAND,
            links.on_message,
            block=False,
        )
    )

    application.add_error_handler(on_error)

    log.info("starting polling…")
    application.run_polling(
        allowed_updates=Update.ALL_TYPES, drop_pending_updates=True
    )


if __name__ == "__main__":
    main()
