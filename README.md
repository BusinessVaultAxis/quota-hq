# Quota HQ

Sales dashboard, payouts and rep portal for Quota. Node + Postgres, deployed on Railway.

- `server.js` — logins, invites, recruit links, role-based data API
- `public/index.html` — the app (built from the Quota HQ page with `node build.js <page.html>`)
- `public/login.html`, `public/join.html` — sign-in, set-password and recruit pages
- `data/seed.json` — one-time import, loaded only into an empty database

Env: `DATABASE_URL`, `SESSION_SECRET`, `BASE_URL`, `ADMIN_EMAIL`.
