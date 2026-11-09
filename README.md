# Telegram Bypass Bot — Compact 7-file Render package

This distribution keeps the original bot implementation, handlers, database backends, services, URL/domain database, dashboard templates, dashboard CSS, and offline smoke tests inside `app.py`. The launcher unpacks the bundled runtime into the system temporary directory at startup; no source files need to be uploaded separately.

## Render deployment

1. Upload these **seven files** to a GitHub repository.
2. In Render, create a Blueprint from that repository (or create a Python Web Service manually).
3. Set `BOT_TOKEN`, `ADMIN_IDS`, and a strong `WEB_ADMIN_PASSWORD` in Render Environment. `ADMIN_IDS` is a comma-separated list of numeric Telegram user IDs.
4. Keep the persistent disk mounted at `/data`; the SQLite database and heartbeat use that directory.
5. Deploy. The bot polls Telegram and the protected dashboard is served by the same process. Open the service URL and log in with your numeric Telegram admin ID and `WEB_ADMIN_PASSWORD`.

Build: `pip install -r requirements.txt`  
Start: `python app.py`  
Health check: `/_ping`

## Local run

Install dependencies with `pip install -r requirements.txt`, set the environment variables (see `.env.example`), then run `python app.py`.

## Notes

- Do not commit real bot tokens, admin passwords, or database credentials.
- Render's persistent disk requires a paid instance. Without persistent storage, SQLite data may be lost on redeploy/restart.
- Keep `AUTO_UPDATE=false` unless you intentionally want the bot's dependency updater to install newer package versions.
- The embedded original smoke test is available after extraction at `tests/smoke_test.py`; run it with `python /tmp/telegram-bot-runtime-*/tests/smoke_test.py` after dependencies are installed.
- All original bot features and source modules are bundled rather than rewritten.
