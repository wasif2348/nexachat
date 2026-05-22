# NexaChat

**A full-stack real-time chat platform built for cybersecurity research.**

NexaChat is an enterprise-style messaging application — rooms, profiles, file sharing, admin controls, and live reactions — built on Node.js, Socket.io, and SQLite. It was designed with a dual purpose: to look and feel like a real production chat app, while containing a set of deliberately implemented security vulnerabilities that can be detected and blocked live using the [ShieldWatch Sensor](https://github.com/YOUR_USERNAME/shieldwatch-sensor).

> **CS-471 Final Project** — Air University Islamabad
> Demonstrates Runtime Application Self-Protection (RASP) against 10 real attack categories.

---

## Table of Contents

- [What It Is](#what-it-is)
- [Features](#features)
- [Demo Accounts](#demo-accounts)
- [Deliberate Vulnerabilities](#deliberate-vulnerabilities)
- [Tech Stack](#tech-stack)
- [Running Locally](#running-locally)
- [Enabling ShieldWatch Protection](#enabling-shieldwatch-protection)
- [Deploying to EC2](#deploying-to-ec2)
- [Project Structure](#project-structure)
- [Demo Attack Scripts](#demo-attack-scripts)

---

## What It Is

NexaChat presents as a real-world enterprise chat platform. Users can register, log in, join rooms, send messages, react with emojis, share files, and use @mentions. Admins can kick users, mute them, pin messages, set slow mode, and send global announcements.

Behind the scenes, several endpoints are intentionally written with classic security mistakes — SQL injection, XSS, path traversal, command injection, CSRF, IDOR, session fixation, and brute force exposure. These are not accidents. They are the attack surface that ShieldWatch RASP protects against during the live demo.

---

## Features

### Chat
- Real-time messaging via Socket.io — no page refresh ever needed
- Persistent message history (SQLite, last 100 messages per room)
- Emoji reactions — click any emoji to react, see who reacted inline with hover tooltip
- Reply threading — hover a message, click reply, sends a quoted reply in-context
- @mention system — type `@` to open a live dropdown of online users, Tab or Enter to complete
- Message deletion — soft delete with tombstone, broadcast to everyone in the room
- Slow mode — admin sets a per-room cooldown (5s, 10s, 30s, 60s) enforced server-side

### Rooms
- Five default rooms: General, Tech, Random, Gaming, Music
- Room switching with search panel (sidebar search + full search overlay with Ctrl+K)
- Pinned message banner — admin pins a message, it shows at the top of the channel for everyone
- Pinned messages persist across page reloads (stored in database)

### Users & Profiles
- Registration and login with session-based auth
- Avatar color — randomly assigned on registration, shown in all messages
- User profiles with bio, displayed in sidebar member list
- Online/offline status synced in real time

### Admin Controls (admin role only)
- **Kick user** — force-disconnects with a visible overlay on the kicked user's screen
- **Mute user** — server-enforced with duration options (1 min, 5 min, 30 min, permanent). Muted users see an error if they try to send
- **Pin message** — pins any message as a room-wide banner
- **Slow mode** — per-room rate limiter. Users who send too fast get blocked server-side
- **Global broadcast** — sends a system announcement to every room simultaneously
- **Admin toolbar** visible only to admin-role users

### File Sharing
- Upload files directly in chat
- Files stored in `/uploads/` and served statically
- Download link sent as a chat message

### Security Integration
- ShieldWatch RASP middleware scans every HTTP request before it reaches any route
- WebSocket messages scanned for XSS/SQLi before being broadcast
- Browser fingerprinting — every login page generates a one-time nonce; the JS beacon collects canvas, WebGL, screen, timezone, and GPU data and submits it before login is allowed
- Fingerprint blocks survive VPN/IP rotation (device is tracked, not just IP)
- Brute force tracking — failed logins counted per IP, auto-block at threshold
- Honeypot paths — probing `/admin`, `/.env`, `/wp-admin`, etc. immediately flags the IP in the ShieldWatch dashboard

---

## Demo Accounts

These accounts are seeded automatically when the database is created.

| Username | Password  | Role  | Notes                            |
|----------|-----------|-------|----------------------------------|
| admin    | admin123  | Admin | Full admin toolbar in chat       |
| alice    | alice123  | User  | Good demo "victim" account       |
| bob      | bob123    | User  | Good demo "second user" account  |
| attacker | hack3r    | User  | Good demo "attacker" account     |

---

## Deliberate Vulnerabilities

> ⚠️ These vulnerabilities are **intentional**. They exist so ShieldWatch can detect and block them live during the demonstration. **Do not use NexaChat as a base for any real production application.**

| # | Vulnerability | Endpoint | Payload |
|---|---------------|----------|---------|
| 1 | **SQL Injection** | `POST /api/login` | Username: `admin'--` with any password |
| 2 | **Reflected XSS** | `GET /api/search?q=` | `<img src=x onerror=alert(1)>` |
| 3 | **Path Traversal** | `GET /api/file?path=` | `../../private/db_config.txt` |
| 4 | **Command Injection** | `POST /api/tools/ping` | `{ "host": "8.8.8.8 && id" }` |
| 5 | **CSRF** | `POST /api/profile/update` | Cross-origin form submission |
| 6 | **IDOR** | `GET /api/user/:id` | Any user ID — returns plaintext password |
| 7 | **Session Fixation** | `GET /api/session/id` + `GET /api/session/fix` | Exposes and accepts arbitrary session IDs |
| 8 | **Brute Force** | `POST /api/login` | No lockout without ShieldWatch |
| 9 | **DDoS** | Any `/api/*` route | Flood with parallel requests |
| 10 | **Honeypot** | `/admin`, `/.env`, etc. | Accessing decoy paths flags the attacker |

With ShieldWatch enabled (`SW_ENABLED=true`), all of these are detected and blocked in real time. Without it, every single one works.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Node.js ≥ 18 |
| Framework | Express 4 |
| Real-time | Socket.io 4 |
| Database | SQLite via sql.js (pure JS, no native binaries) |
| Sessions | express-session |
| Security | shieldwatch-sensor (RASP middleware) |
| Frontend | Vanilla JS + CSS (no framework) |
| Font | System default (Inter/SF Pro/Segoe UI) |

---

## Running Locally

### Requirements
- Node.js 18 or higher
- npm

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/nexachat.git
cd nexachat

# 2. Install dependencies
npm install

# 3. Start the server
node server.js
```

Open `http://localhost:3001` in your browser.

The database is created automatically on first run. All five rooms and four demo accounts are seeded immediately.

### Running Without ShieldWatch (unprotected — all vulnerabilities work)

```bash
node server.js
```

### Running With ShieldWatch (protected — all attacks blocked)

```bash
SW_ENABLED=true SW_CEREBRO_URL=http://localhost:3002 node server.js
```

ShieldWatch Sensor must be installed (already in `package.json`). The Cerebro dashboard (collector) must be running on port 3002 to receive events — but ShieldWatch will still block attacks even if Cerebro is offline.

---

## Enabling ShieldWatch Protection

ShieldWatch is installed as a dependency and controlled by environment variables.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SW_ENABLED` | `false` | Set to `"true"` to activate the sensor |
| `SW_CEREBRO_URL` | `http://localhost:3002` | URL of the Cerebro dashboard backend |
| `SW_APP_ID` | `nexachat` | Label shown in Cerebro for this app |
| `SW_LOG_ONLY` | `false` | `"true"` = detect but never block (passive mode) |

### What ShieldWatch Does in NexaChat

Once `SW_ENABLED=true`:

1. Every HTTP request is scanned before it reaches any route — SQLi, XSS, path traversal, command injection, SSRF, CRLF
2. Login page loads a fingerprint nonce — login is gated behind the JS beacon completing
3. Failed logins are tracked per IP — auto-block at 5 failures in 60 seconds
4. The `/api/profile/update` endpoint rejects form-encoded cross-origin submissions (CSRF)
5. `/api/session/id` and `/api/session/fix` are blocked (session fixation endpoints)
6. `/api/user/:id` checks ownership — accessing another user's record is blocked (IDOR)
7. API flood detection — more than 20 requests in 10 seconds from one IP = blocked
8. Honeypot paths (`/admin`, `/.env`, etc.) flag the IP in Cerebro immediately
9. WebSocket messages are scanned before being broadcast to the room
10. All events sent to Cerebro in real time — attacker fingerprint, IP, payload, verdict

---

## Deploying to EC2

This is the recommended deployment path for the class demo.

### One-Time Setup

```bash
# On your EC2 instance (Ubuntu)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm install -g pm2

# Clone and install
git clone https://github.com/YOUR_USERNAME/nexachat.git ~/nexachat
cd ~/nexachat
npm install

# Start with PM2
pm2 start server.js --name nexachat
pm2 save
pm2 startup   # follow the command it prints to auto-start on reboot
```

### Enabling ShieldWatch on EC2

**Option A — Set env vars inline (quick test):**
```bash
SW_ENABLED=true SW_CEREBRO_URL=https://YOUR_NGROK_URL node server.js
```

**Option B — PM2 ecosystem file (persistent, recommended):**

Create `ecosystem.config.js` in `~/nexachat/`:

```javascript
module.exports = {
  apps: [{
    name: 'nexachat',
    script: 'server.js',
    env: {
      NODE_ENV:      'production',
      PORT:          '3001',
      SESSION_SECRET: 'change-this-to-a-random-string',
      SW_ENABLED:    'true',
      SW_CEREBRO_URL: 'https://YOUR_NGROK_URL_HERE',
      SW_APP_ID:     'nexachat-ec2',
    }
  }]
};
```

Then:
```bash
pm2 start ecosystem.config.js
pm2 save
```

### Updating After a Code Change

```bash
cd ~/nexachat && git pull && pm2 restart nexachat
```

### Checking Logs

```bash
pm2 logs nexachat
```

Look for:
```
[ShieldWatch] ✅ RASP sensor ACTIVE — Cerebro: https://YOUR_NGROK_URL
```
or
```
[ShieldWatch] ⛔ Sensor DISABLED — app is UNPROTECTED
```

---

## Project Structure

```
nexachat/
├── server.js              Main Express + Socket.io server
├── database.js            SQLite setup, migrations, seed data
├── package.json
├── ecosystem.config.js    PM2 deployment config for EC2
│
├── public/
│   ├── index.html         Login page
│   ├── chat.html          Main chat interface
│   ├── chat.css           All styles
│   ├── chat.js            All client-side logic
│   └── sw-beacon.js       ShieldWatch browser fingerprint collector
│
├── private/
│   └── db_config.txt      Fake secret file — used for path traversal demo
│
├── uploads/               Uploaded files (created automatically)
│
├── brute-force.js         Demo: automated brute force against /api/login
└── ddos-flood.js          Demo: parallel DDoS flood against /api/login
```

---

## Demo Attack Scripts

Two scripts are included for live demo use.

### DDoS Flood

```bash
node ddos-flood.js
```

Fires 50 parallel requests at `/api/login`. Without ShieldWatch all 50 go through. With ShieldWatch the first 20 pass, then all remaining are blocked with HTTP 429.

### Brute Force

```bash
node brute-force.js
```

Tries 30 common passwords against the `admin` account at 150ms intervals. Without ShieldWatch it succeeds when it hits `admin123`. With ShieldWatch it gets blocked after 5 failures.

---

## Security Notice

This application is **intentionally vulnerable** for educational and demonstration purposes. It must never be deployed as a real user-facing service without removing all deliberate vulnerabilities. The authors take no responsibility for misuse.

---

## License

MIT
