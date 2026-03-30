# Half Off Hub

50% off orders site with password protection and Discord webhook notifications.

## Local Setup

1. `npm install`
2. Copy `.env.example` to `.env` and add your Discord webhook URLs
3. `npm start`
4. Visit `http://localhost:3000`

New password auto-generated every 24h and sent to SECURITY_WEBHOOK_URL.

## GitHub Deployment

1. Push all files to GitHub repo
2. Go to repo Settings > Secrets and variables > Actions
3. Add these repo secrets:
   - `SECURITY_WEBHOOK_URL` = your discord security webhook
   - `ORDER_WEBHOOK_URL` = your discord order webhook (or same)
4. (Optional) `ATTEMPT_GIF_URL`

## Railway Deployment (Recommended)

1. Connect GitHub repo to Railway
2. In Railway service variables, add:
   ```
   SECURITY_WEBHOOK_URL = https://discord.com/api/...
   ORDER_WEBHOOK_URL = https://discord.com/api/...
   PORT = 3000 (auto-detected)
   ```
3. Deploy! Railway assigns domain.

## Env Vars Explained

- `SECURITY_WEBHOOK_URL`: Discord webhook for new passwords + failed/successful login attempts + blocks
- `ORDER_WEBHOOK_URL`: Discord webhook for submitted orders (fallback to security if empty)
- `ATTEMPT_GIF_URL`: Optional GIF embed on login attempts

## Troubleshooting

**"Order webhook is not configured"**
- Set `ORDER_WEBHOOK_URL` in Railway/GitHub vars
- Redeploy service

**No password received**
- Check SECURITY_WEBHOOK_URL is valid Discord webhook
- Server generates/sends on first startup or every 24h

**Check server logs**
```
Server running on http://localhost:3000
Security webhook configured: yes/no
Order webhook configured: yes/no
```

## Files

- `server.js`: Main Node.js/Express server
- `index.html`: Landing + password overlay
- `protected/tool-fragment.html`: Order form (loaded after unlock)
- `attempt-log.jsonl`: Login attempt logs
- `password.json`: Current 24h password (auto rotates)

