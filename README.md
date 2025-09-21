# Secure Redirect (Railway-ready)

This project implements a secure redirect flow with client-side bot detection and Telegram logging. Intended for deployment on Railway.

## Environment variables
- `REDIRECT_SECRET`
- `ALLOWED_REF`
- `REDIRECT_URL`
- `TELEGRAM_TOKEN` (optional)
- `TELEGRAM_CHAT_ID` (optional)

## Deploy
1. Push repo to GitHub
2. Deploy on Railway
3. Add env vars

Run locally:
```
npm install
npm start
```
