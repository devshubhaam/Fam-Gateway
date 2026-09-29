# UPIBridge

Non-custodial UPI payment verification + signed webhooks. Flask + MongoDB, built to deploy on Render.
Design ported from the FamGateway landing page you supplied (own branding, own copy).

## Deploy on Render
1. Push this folder to a GitHub repo (replace whole files, no partial edits needed).
2. New > Blueprint (uses `render.yaml`) or a Web Service with:
   - Build: `pip install -r requirements.txt`
   - Start: `gunicorn app:app --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:$PORT`
3. Env vars: `MONGODB_URI` (Atlas), `SECRET_KEY` (long random; do not change later or stored mailbox passwords become unreadable), `BASE_URL` (your https URL), optional `BRAND_NAME`.
4. Open the site > Register > Dashboard: save UPI ID, mailbox, then press **Create test order**.
5. After you have your account, set `ALLOW_REGISTRATION=0` if this is only for you.

Keep it to ONE gunicorn worker: the mailbox poller and webhook sender run in that process.
Render's free plan sleeps after ~15 min idle, which pauses polling. Use a paid instance or an uptime pinger on `/healthz`.

## Mailbox setup
Use a dedicated Gmail: turn on 2-step verification, create an App Password, enable IMAP, and forward your bank/UPI-app credit alerts to it.
Put the alert sender (address or domain) in "Allowed senders". Leave "Require DKIM/DMARC" on unless the dashboard's
"Recent emails" table shows your genuine alerts being rejected for that reason.

## Tuning the email parser
Bank/app emails differ. Defaults live at the top of `mailparse.py` (`CREDIT_WORDS`, `AMOUNT_RE`, `UTR_RES`).
The dashboard's "Recent emails" table shows what happened to each alert (ignored / rejected / matched).

## Tests
`python3 -m unittest tests.test_flow` (uses an in-memory fake of pymongo, no database needed).
