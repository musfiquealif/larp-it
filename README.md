# LARP It Till You Make It: site + push server

One small Node app (no dependencies, Node 18+) that serves the site **and** sends real push notifications to phones that installed it.

## Run locally
    ADMIN_TOKEN=$(openssl rand -hex 24) node server.js     # http://localhost:3000, admin at /admin
    npm test                                               # end-to-end push test (mock push service)

## Deploy (needs a host that runs Node: Render, Railway, Fly.io, a VPS. Static hosts like Vercel/Netlify alone won't do)
1. Push this folder to a Git repo and create a **web service** (start command `node server.js`).
2. Set env vars:
   - `ADMIN_TOKEN`: long random secret (required, 16+ chars). It protects /admin and every send.
   - `VAPID_KEYS` (**required on free hosts with a temporary disk**): the JSON key from `data/vapid.json` of a local run, or generate one with `node -e "console.log(JSON.stringify(require('crypto').generateKeyPairSync('ec',{namedCurve:'prime256v1'}).privateKey.export({format:'jwk'})))"`. Keep it private. If the keys change, the app re-registers itself next time it opens.
   - `DATA_DIR` (optional): folder on a persistent disk for subscribers. If the disk is temporary, phones simply re-register next time they open the app.
   - `VAPID_SUBJECT` (optional): `mailto:you@yourdomain.com`.
3. Point larpittillyoumakeit.com at the service (HTTPS is required for push).

## On your iPhone (iOS 16.4+)
1. Open the site in **Safari** > Share > **Add to Home Screen**.
2. Open it from the new icon (not Safari) > **Enable notifications** > Allow.
3. On any device open `https://larpittillyoumakeit.com/admin`, enter your token, and send: now, after a delay, or a stream of sales.

## Limits worth knowing
- Scheduled runs live in server memory. A restart or redeploy cancels them.
- The server holds up to 100 subscribed devices.
- iOS decides delivery timing, and may drop pushes if the app is never opened or notifications get silenced.
- Parody tool: keep it to pranks and screenshots among people who know.
